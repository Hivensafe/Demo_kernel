// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_all — block writes to block devices (partitions) by default,
 * allow only known-safe partitions/processes; no SELinux dependency.
 *
 * Key points:
 *  - Gated activation: do nothing until /data is mounted OR zygote is observed.
 *  - Hot-path optimizations: likely/unlikely, __always_inline, small hashtables.
 *  - Allowlist:
 *      * Partitions: boot/init_boot/dtbo/vendor_boot + userdata/cache/metadata/misc
 *        -> resolve by-name (with slot variants) to dev_t and cache, then defer (allow).
 *      * Processes: fuzzy match by comm substring (update_engine, fastbootd, recovery,
 *        rmt_storage, fsck, bootctl, mkswap, etc.) -> allow.
 *  - First-write reverse allow: first time we see a dev_t, try resolve by-name allowlist;
 *    on hit, cache as allowed; otherwise cache in denied_seen and block.
 *  - Logs: rate-limited; only print pid & argv; quiet window after boot.
 *
 * Hooks: file_permission (writes), file_ioctl (+ compat >=6.6) for destructive ioctls.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/workqueue.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ===== 进程名模糊放行（不依赖 SELinux）===== */
static const char * const allowed_comm_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"bootctl",              /* hal_bootctl_default 等 */
	"fsck",
	"mkswap",
	"charger",              /* vendor.oplus.hardware.charger* 自检 */
	"oplus", "oppo",        /* 厂商自检脚本（可按需收窄） */
	"vendor_qti", "feature" /* 有些厂商“feature”更新器 */
};
static const size_t allowed_comm_cnt = ARRAY_SIZE(allowed_comm_substrings);

/* ===== 分区 allowlist（命中则直接允许）===== */
static const char * const allowlist_names[] = {
	/* 可自由刷写的启动相关 */
	"boot", "init_boot", "dtbo", "vendor_boot",
	/* 保证系统可用性的分区 */
	"userdata", "cache", "metadata", "misc", "zarm0"
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== A/B slot 后缀（只解析一次）===== */
extern char *saved_command_line; /* from init/main.c */
static const char *bbg_slot_suffix __read_mostly;
static __always_inline const char *slot_suffix_from_cmdline_once(void)
{
	const char *p = saved_command_line;
	if (!p) return NULL;
	p = strstr(p, "androidboot.slot_suffix=");
	if (!p) return NULL;
	p += strlen("androidboot.slot_suffix=");
	if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b'))
		return (p[1] == 'a') ? "_a" : "_b";
	return NULL;
}

/* ===== 就绪门控：/data 或 zygote 出现后再启用 ===== */
static struct delayed_work bbg_poll_work;
static struct workqueue_struct *bbg_wq;
static unsigned int poll_interval_ms __read_mostly = 500;
module_param(poll_interval_ms, uint, 0644);
MODULE_PARM_DESC(poll_interval_ms, "Polling interval (ms) for /data & zygote readiness");

static bool bbg_ready; /* 一旦 true，钩子开始工作 */

static __always_inline bool bbg_data_mounted_once(void)
{
	struct path p;
	if (kern_path("/data", LOOKUP_FOLLOW, &p) == 0) {
		path_put(&p);
		return true;
	}
	return false;
}

static __always_inline bool bbg_zygote_seen_once(void)
{
	struct task_struct *g, *t;
	bool seen = false;
	rcu_read_lock();
	for_each_process_thread(g, t) {
		/* zygote 可表现为 app_process64/32，也可能是 app_main 包装 */
		if (!t->comm) continue;
		if (strstr(t->comm, "app_process") || strstr(t->comm, "zygote")) {
			seen = true;
			break;
		}
	}
	rcu_read_unlock();
	return seen;
}

static void bbg_poll_worker(struct work_struct *ws)
{
	if (likely(bbg_ready))
		return;

	if (bbg_data_mounted_once() || bbg_zygote_seen_once()) {
		bbg_ready = true;
#if BB_VERBOSE
		bb_pr("READY (gated by /data or zygote)\n");
#endif
		return;
	}
	/* 继续轮询 */
	queue_delayed_work(bbg_wq, &bbg_poll_work, msecs_to_jiffies(poll_interval_ms));
}

/* ===== by-name -> dev_t（统一实现，兼容 5.10~6.6）===== */
static __always_inline bool resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	struct path p;
	struct inode *inode;

	if (!name || !out) return false;
	path = kasprintf(GFP_ATOMIC, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

	if (kern_path(path, LOOKUP_FOLLOW, &p)) {
		kfree(path);
		return false;
	}
	kfree(path);

	inode = d_backing_inode(p.dentry);
	if (!inode || !S_ISBLK(inode->i_mode)) {
		path_put(&p);
		return false;
	}

	*out = inode->i_rdev;
	path_put(&p);
	return true;
}

/* ===== 允许 dev_t 缓存 ===== */
struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 8); /* 256 buckets */

static __always_inline bool allow_has(dev_t dev)
{
	struct allow_node *p;
	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static __always_inline void allow_add(dev_t dev)
{
	struct allow_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(allowed_devs, &n->h, (u64)dev);
#if BB_VERBOSE
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
#endif
}

/* ===== 拒绝过的 dev_t（避免重复反查）===== */
struct seen_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(denied_seen, 8);

static __always_inline bool denied_seen_has(dev_t dev)
{
	struct seen_node *p;
	hash_for_each_possible(denied_seen, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}
static __always_inline void denied_seen_add(dev_t dev)
{
	struct seen_node *n;
	if (!dev || denied_seen_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(denied_seen, &n->h, (u64)dev);
}

/* ===== 分区白名单解析（含 slot 变体）===== */
static bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i; dev_t d; bool ok;
	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];

		ok = resolve_byname_dev(n, &d);
		if (ok && d == cur) return true;

		if (bbg_slot_suffix) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", n, bbg_slot_suffix);
			if (nm) {
				ok = resolve_byname_dev(nm, &d);
				kfree(nm);
				if (ok && d == cur) return true;
			}
		} else {
			char *na = kasprintf(GFP_ATOMIC, "%s_a", n);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", n);
			if (na) {
				ok = resolve_byname_dev(na, &d);
				kfree(na);
				if (ok && d == cur) { if (nb) kfree(nb); return true; }
			}
			if (nb) {
				ok = resolve_byname_dev(nb, &d);
				kfree(nb);
				if (ok && d == cur) return true;
			}
		}
	}
	return false;
}

/* ===== 首写反查（命中白名单则缓存）===== */
static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== 进程 comm 模糊放行 ===== */
static __always_inline bool current_comm_allowed_fast(void)
{
	size_t i;
	const char *c = current->comm;
	if (!c || !*c) return false;
	for (i = 0; i < allowed_comm_cnt; i++) {
		const char *needle = allowed_comm_substrings[i];
		if (needle && *needle && strstr(c, needle))
			return true;
	}
	return false;
}

/* ===== 启动静默 & 每设备日志限流 ===== */
static unsigned int quiet_boot_ms __read_mostly = 8000;
module_param(quiet_boot_ms, uint, 0644);
MODULE_PARM_DESC(quiet_boot_ms, "Silent deny logs window (ms) after module init");

static unsigned int per_dev_log_limit __read_mostly = 1;
module_param(per_dev_log_limit, uint, 0644);
MODULE_PARM_DESC(per_dev_log_limit, "Max deny logs per block dev_t this boot");

static unsigned long bbg_boot_jiffies;

struct log_node { dev_t dev; u32 cnt; struct hlist_node h; };
DEFINE_HASHTABLE(denied_logged, 8);

static __always_inline bool bbg_should_log(dev_t dev)
{
	struct log_node *p;
	if (!dev) return false;

	hash_for_each_possible(denied_logged, p, h, (u64)dev) {
		if (p->dev == dev) {
			if (p->cnt >= per_dev_log_limit) return false;
			p->cnt++;
			return true;
		}
	}
	p = kmalloc(sizeof(*p), GFP_ATOMIC);
	if (!p) return false;
	p->dev = dev;
	p->cnt = 1;
	hash_add(denied_logged, &p->h, (u64)dev);
	return true;
}

/* ===== 仅采集 argv 的小工具（冷路径）===== */
static __cold noinline int bbg_get_cmdline(char *buf, int buflen)
{
	int n, i;
	if (!buf || buflen <= 0) return 0;
	n = get_cmdline(current, buf, buflen);
	if (n <= 0) return 0;
	for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
	if (n < buflen) buf[n] = '\0';
	else buf[buflen - 1] = '\0';
	return n;
}

static __cold noinline void bbg_log_deny(unsigned int cmd_opt, struct file *file)
{
	const int CMD_BUFLEN = 256;
	char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
	if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info_ratelimited("baseband_guard: deny pid=%d argv=\"%s\"\n",
				    current->pid, cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited("baseband_guard: deny pid=%d argv=\"%s\"\n",
				    current->pid, cmdbuf ? cmdbuf : "?");
	}
	kfree(cmdbuf);
}

static __cold noinline int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;

	/* 静默窗口：强制拒绝但不打印 */
	if (quiet_boot_ms &&
	    time_before(jiffies, bbg_boot_jiffies + msecs_to_jiffies(quiet_boot_ms)))
		return -EPERM;

	/* 每设备限流 */
	if (file) {
		struct inode *inode = file_inode(file);
		if (inode && S_ISBLK(inode->i_mode)) {
			dev_t dev = inode->i_rdev;
			if (!bbg_should_log(dev))
				return -EPERM;
		}
	}

	bbg_log_deny(cmd_opt, file);
	return -EPERM;
}

/* ===== 只拦写、只拦破坏性 ioctl；满足条件才开始生效 ===== */
static __always_inline bool is_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
#ifdef BLKPG
	case BLKPG:
#endif
#ifdef BLKTRIM
	case BLKTRIM:
#endif
#ifdef BLKRRPART
	case BLKRRPART:
#endif
#ifdef BLKSETRO
	case BLKSETRO:
#endif
#ifdef BLKSETBADSECTORS
	case BLKSETBADSECTORS:
#endif
		return true;
	default:
		return false;
	}
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	/* 未就绪：完全不介入，避免早期误拦 */
	if (unlikely(!bbg_ready)) return 0;

	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	/* 进程名模糊放行（如 update_engine / rmt_storage 等） */
	if (unlikely(current_comm_allowed_fast()))
		return 0;

	rdev = inode->i_rdev;

	/* 分区命中 allowlist（含缓存、反查）→ 允许 */
	if (likely(allow_has(rdev)))
		return 0;
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	/* miss：记忆并拒绝 */
	denied_seen_add(rdev);
	return deny("write to protected partition", file, 0);
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	dev_t rdev;

	if (unlikely(!bbg_ready)) return 0;

	if (unlikely(!file)) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(!is_destructive_ioctl(cmd)))
		return 0;

	/* 进程名模糊放行 */
	if (unlikely(current_comm_allowed_fast()))
		return 0;

	rdev = inode->i_rdev;

	if (likely(allow_has(rdev)))
		return 0;
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	denied_seen_add(rdev);
	return deny("destructive ioctl on protected partition", file, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ===== LSM 注册 & 初始化 ===== */
static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,   bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,        bb_file_ioctl),
#ifdef BB_HAVE_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");

	/* slot 后缀一次性解析 */
	bbg_slot_suffix = slot_suffix_from_cmdline_once();

	/* 启动门控轮询（/data 或 zygote） */
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (bbg_wq) {
		INIT_DELAYED_WORK(&bbg_poll_work, bbg_poll_worker);
		queue_delayed_work(bbg_wq, &bbg_poll_work, 0);
	}

	bbg_boot_jiffies = jiffies;
	pr_info("baseband_guard_all (gated by /data or zygote; perf-optimized; limited logs)\n");
	return 0;
}

static void __exit bbg_exit(void)
{
	if (bbg_wq) {
		cancel_delayed_work_sync(&bbg_poll_work);
		destroy_workqueue(bbg_wq);
	}
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

module_init(bbg_init);
module_exit(bbg_exit);

MODULE_DESCRIPTION("Baseband guard (no-SELinux dep): gated activation, optimized hot path, limited logs");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");