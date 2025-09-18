// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_all: global partition write guard with SELinux-enforcing gated activation
 *
 * - Boots in IDLE: no interception to avoid early-boot false positives.
 * - Becomes READY when /data is mounted or zygote pre-exec is observed.
 * - Polls SELinux enforcing every 500ms (weak symbol + cmdline fallback).
 * - Activates only after confirming enforcing, then:
 *     * Global block for writes / destructive ioctls to block devices
 *     * Allowlist domains (substring) → defer to SELinux (return 0)
 *     * Allowlist partitions (boot/init_boot/dtbo/vendor_boot/userdata/cache/metadata/misc) → defer to SELinux
 *     * Others → -EPERM
 *
 * 5.10 ~ 6.6 compatible (no reliance on lookup_bdev prototype; uses kern_path).
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
#include <linux/workqueue.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#define BB_ENFORCING 1
#define BB_DIAG 0 /* 设为 1 可打开诊断期“每次拒绝都打 enforcing/domain/argv” */

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

extern char *saved_command_line; /* from init/main.c */

/* ===== 允许放行的 SELinux 域（子串匹配，仅在严格模式生效） ===== */
static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"update_engine_sideload",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"hal_bootctl",
	"fsck",
	"swap",
	"nandswap",
	"feature",
	"vendor_qti",
	"system_perf_init",
	"mi_ric",
	"oplus", "oppo",
};
static const size_t allowed_domain_substrings_cnt =
	ARRAY_SIZE(allowed_domain_substrings);

/* ===== 放行分区（交由 SELinux 决定，不提前投“允许票”） ===== */
static const char * const allowlist_names[] = {
	/* 刷机自由 */
	"boot", "init_boot", "dtbo", "vendor_boot",
	/* 系统可用性 */
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== slot suffix once ===== */
static const char *bbg_slot_suffix;
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

/* ===== 弱符号：优先用安全接口拿 SELinux enforcing ===== */
#ifdef CONFIG_SECURITY_SELINUX
extern int security_getenforce(void) __attribute__((weak));
#endif

/* ===== 状态机 ===== */
enum run_state { ST_IDLE = 0, ST_READY = 1, ST_ACTIVE = 2 };
static volatile unsigned int bbg_state;
static struct delayed_work bbg_poll_work;
static struct workqueue_struct *bbg_wq;
static unsigned int poll_interval_ms = 500; /* 500ms 轮询 SELinux 状态 */
module_param(poll_interval_ms, uint, 0644);
MODULE_PARM_DESC(poll_interval_ms, "Polling interval (ms) while READY");

/* ===== 只在 ACTIVE 使用的缓存结构（热路径） ===== */
struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 8); /* 放行分区 dev_t 缓存 */

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
}

/* 首次 miss 见到的 dev_t（非放行分区）记录，用于避免重复反查 */
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

/* ===== by-name -> dev_t 解析（统一实现，兼容 5.10~6.6） ===== */
static __always_inline bool resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	struct path p;
	struct inode *inode;
	int ret;

	if (!name || !out) return false;
	path = kasprintf(GFP_ATOMIC, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

	ret = kern_path(path, LOOKUP_FOLLOW, &p);
	kfree(path);
	if (ret)
		return false;

	inode = d_backing_inode(p.dentry);
	if (!inode || !S_ISBLK(inode->i_mode)) {
		path_put(&p);
		return false;
	}
	*out = inode->i_rdev;
	path_put(&p);
	return true;
}

/* ===== 放行分区：首写反查 + slot 变体 ===== */
static __always_inline bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i;
	dev_t dev;
	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];
		bool ok = false;

		if (resolve_byname_dev(n, &dev) && dev == cur) return true;

		if (!ok && bbg_slot_suffix) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", n, bbg_slot_suffix);
			if (nm) {
				ok = resolve_byname_dev(nm, &dev);
				kfree(nm);
				if (ok && dev == cur) return true;
			}
		}
		if (!ok) {
			char *na = kasprintf(GFP_ATOMIC, "%s_a", n);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", n);
			if (na) {
				ok = resolve_byname_dev(na, &dev);
				kfree(na);
				if (ok && dev == cur) { if (nb) kfree(nb); return true; }
			}
			if (nb) {
				ok = resolve_byname_dev(nb, &dev);
				kfree(nb);
				if (ok && dev == cur) return true;
			}
		}
	}
	return false;
}

static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== 运行时 flags ===== */
static bool enforcing_latched;   /* 成功确认严格模式后置 1 */
static bool in_recovery_mode;    /* fastboot/recovery 模式下，一直停在 IDLE */

/* ===== /data & zygote 观察 ===== */
static __always_inline void bbg_mark_ready(void)
{
	if (bbg_state == ST_IDLE) {
		bbg_state = ST_READY;
#if BB_DIAG
		pr_info("baseband_guard: READY (will poll enforcing)\n");
#endif
		if (bbg_wq)
			queue_delayed_work(bbg_wq, &bbg_poll_work, 0);
	}
}

static int bbg_sb_mount(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data)
{
	/* 只看最终挂载点名为 "data" 的情况（/data） */
	if (path && path->dentry) {
		const char *leaf = path->dentry->d_name.name;
		if (leaf && !strcmp(leaf, "data")) {
#if BB_DIAG
			pr_info("baseband_guard: /data is mounted\n");
#endif
			bbg_mark_ready();
		}
	}
	return 0; /* 永远不干预挂载 */
}

/* 识别 zygote 的预执行路径（仅用于推进 READY） */
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

static int bbg_bprm_check_security(struct linux_binprm *bprm)
{
	size_t i;
	const char *path;

	if (!bprm || !bprm->filename)
		return 0;
	path = bprm->filename;
	for (i = 0; i < ZYGOTE_CAND_CNT; i++) {
		if (!strcmp(path, zygote_candidates[i])) {
#if BB_DIAG
			pr_info("baseband_guard: zygote detected (pid=%d)\n", current->pid);
#endif
			bbg_mark_ready();
			break;
		}
	}
	return 0;
}

/* ===== SELinux 严格模式判断 ===== */
static __always_inline bool cmdline_enforcing(void)
{
	const char *p = saved_command_line;
	if (!p) return false;
	return strstr(p, "androidboot.selinux=enforcing") != NULL;
}
static __always_inline bool cmdline_is_recovery(void)
{
	const char *p = saved_command_line;
	if (!p) return false;
	return strstr(p, "androidboot.mode=recovery") ||
	       strstr(p, "androidboot.force_recovery") ||
	       strstr(p, "androidboot.fastboot");
}

/* READY 阶段轮询：确认严格即进入 ACTIVE；recovery/fastboot 则一直保持 IDLE */
static void bbg_poll_worker(struct work_struct *ws)
{
	bool enforcing = false;
#ifdef CONFIG_SECURITY_SELINUX
	if (security_getenforce) {
		int e = security_getenforce();
		enforcing = (e > 0);
	}
#endif
	if (!enforcing)
		enforcing = cmdline_enforcing();

	if (enforcing) {
		enforcing_latched = true;
		bbg_state = ST_ACTIVE;
#if BB_DIAG
		pr_info("baseband_guard: ACTIVE (enforcing confirmed)\n");
#endif
		return; /* 不再重排队，停止轮询 */
	}

	/* 未严格，则继续轮询 */
	if (bbg_wq)
		queue_delayed_work(bbg_wq, &bbg_poll_work,
				   msecs_to_jiffies(poll_interval_ms));
}

/* ===== 允许域：仅当严格模式下才生效；用 secid->secctx 做子串匹配 ===== */
static __always_inline bool current_domain_allowed_fast(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0, len = 0;
	char *ctx = NULL;
	size_t i;

	/* 严格模式才考虑放行域 */
	if (likely(!enforcing_latched))
		return false;

	security_cred_getsecid(current_cred(), &sid);
	if (!sid) return false;
	if (security_secid_to_secctx(sid, &ctx, &len) || !ctx || !len)
		return false;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle && strnstr(ctx, needle, len)) {
			security_release_secctx(ctx, len);
			return true;
		}
	}
	security_release_secctx(ctx, len);
	return false;
#else
	return false;
#endif
}

/* ===== 只为诊断打印 domain/argv（非严格意义热路径，不影响性能） ===== */
#if BB_DIAG
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
#endif

static __cold noinline void bbg_log_deny(dev_t dev, const char *why, unsigned int cmd_opt)
{
#if BB_DIAG
	/* 打印 enforcing/domain/argv，帮助诊断是谁在写 */
	char dom[96] = "?";
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0, len = 0; char *ctx = NULL;
	security_cred_getsecid(current_cred(), &sid);
	if (sid && !security_secid_to_secctx(sid, &ctx, &len) && ctx) {
		size_t cpy = min_t(size_t, sizeof(dom) - 1, len);
		memcpy(dom, ctx, cpy); dom[cpy] = '\0';
		security_release_secctx(ctx, len);
	}
#endif
	{
		const int CMD_BUFLEN = 256;
		char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
		if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);
		if (cmd_opt) {
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%s\" argv=\"%s\"\n",
				why, enforcing_latched ? 1 : 0,
				dom, cmdbuf ? cmdbuf : "?");
		} else {
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%s\" argv=\"%s\"\n",
				why, enforcing_latched ? 1 : 0,
				dom, cmdbuf ? cmdbuf : "?");
		}
		kfree(cmdbuf);
	}
#else
	/* 生产默认：只打一条简洁日志（限速） */
	pr_info_ratelimited("baseband_guard: deny %s pid=%d comm=%s\n",
			    why, current->pid, current->comm);
#endif
}

/* ===== deny helper ===== */
static __always_inline int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;
	bbg_log_deny(file ? file_inode(file)->i_rdev : 0, why, cmd_opt);
	return -EPERM;
}

/* ===== ioctl 破坏性判断 ===== */
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

/* ===== 主执法：file_permission (写) ===== */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	/* 未激活前一律不拦截：减少开机期误伤与开销 */
	if (likely(bbg_state != ST_ACTIVE)) return 0;

	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;
	rdev = inode->i_rdev;

	/* 严格模式下允许域：交由 SELinux 决定 */
	if (unlikely(current_domain_allowed_fast()))
		return 0;

	/* 放行分区：直接 defer 给 SELinux */
	if (likely(allow_has(rdev)))
		return 0;

	/* 首次见到：做一次反查，命中放行分区则缓存并 defer */
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	/* 其余：拦截 */
	denied_seen_add(rdev);
	return deny("write to protected partition", file, 0);
}

/* ===== 主执法：file_ioctl (仅破坏性) ===== */
static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	dev_t rdev;

	if (likely(bbg_state != ST_ACTIVE)) return 0;
	if (unlikely(!file)) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(!is_destructive_ioctl(cmd)))
		return 0;

	rdev = inode->i_rdev;

	if (unlikely(current_domain_allowed_fast()))
		return 0;

	if (likely(allow_has(rdev)))
		return 0;

	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	denied_seen_add(rdev);
	return deny("destructive ioctl on protected partition", file, cmd);
}

/* 6.6: file_ioctl_compat 存在；旧核没有则不注册 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ===== LSM 注册 ===== */
static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,   bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,        bb_file_ioctl),
#ifdef BB_HAVE_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,          bbg_sb_mount),
	LSM_HOOK_INIT(bprm_check_security, bbg_bprm_check_security),
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");

	/* recovery/fastboot 模式：永久保持 IDLE（不影响整包刷机） */
	in_recovery_mode = cmdline_is_recovery();
	if (in_recovery_mode) {
		bbg_state = ST_IDLE;
#if BB_DIAG
		pr_info("baseband_guard: recovery/fastboot mode → stay IDLE\n");
#endif
	} else {
		bbg_state = ST_IDLE;
	}

	/* slot 后缀 */
	bbg_slot_suffix = slot_suffix_from_cmdline_once();

	/* 工作队列（只在 READY 阶段用；ACTIVE 后不再调度） */
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_FREEZABLE | WQ_UNBOUND);
	if (bbg_wq)
		INIT_DELAYED_WORK(&bbg_poll_work, bbg_poll_worker);

	pr_info("baseband_guard (%s; /data&zygote poll)\n",
		BB_DIAG ? "diagnostic log build" : "quiet build");

	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("Global partition guard gated by SELinux enforcing; defer allows to SELinux; slot-aware allowlist");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");