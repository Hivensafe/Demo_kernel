// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_autogate (process-only, no SELinux, no cmdline)
 *
 * 目标：
 *   - 拦截对关键基带/引导分区的写入与破坏性 ioctl（BLKDISCARD/BLKPG/BLKTRIM/...）。
 *   - 仅按进程名放过有限的“可信流程”，且静默，不输出日志。
 *   - 一次性 by-name 解析缓存；在缓存构建前通过“反向 dev_t 匹配”兜底，首写也能拦住。
 *   - 通过观察关键挂载点 + Zygote pre-exec 只做一次缓存构建；不循环、不轮询。
 *
 * 可信流程（静默旁路）：
 *   - 写入旁路：update_engine / update_engine_sideload / updata_engien / rmt_storage
 *   - IOCTL 旁路：update_engine / update_engine_sideload / updata_engien
 *   - fastbootd 自身或 ≤4 级祖先进程，视为可信（写入与 ioctl 均旁路）
 *
 * 注意：
 *   - 无任何 SELinux 相关调用或域判断。
 *   - 不依赖内核 cmdline；仅按进程名与祖先链判断。
 *   - 日志仅在拒绝时以 rate-limited 方式输出“deny ...”，旁路路径不输出任何“allow”字样。
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>   /* struct linux_binprm + bprm->filename */
#include <linux/namei.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/param.h>
#include <linux/sched.h>     /* task_struct, TASK_COMM_LEN */
#include <linux/rcupdate.h>  /* rcu_dereference() */

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

struct name_entry { const char *name; u8 st; };
enum res_state { RS_UNKNOWN = 0, RS_OK = 1, RS_FAIL = 2 };

/* === 受保护分区集合（可按机型增删） === */
static struct name_entry core_names[] = {
	{ "xbl", RS_UNKNOWN }, { "xbl_config", RS_UNKNOWN }, { "uefi", RS_UNKNOWN },
	{ "uefisecapp", RS_UNKNOWN }, { "abl", RS_UNKNOWN },
	{ "modem", RS_UNKNOWN }, { "modemst1", RS_UNKNOWN }, { "modemst2", RS_UNKNOWN },
	{ "fsg", RS_UNKNOWN }, { "fsc", RS_UNKNOWN }, { "connsec", RS_UNKNOWN },
	{ "mdm1oemnvbktmp", RS_UNKNOWN }, { "oplusdycnvbk", RS_UNKNOWN }, { "oplusstanvbk", RS_UNKNOWN },
	{ "nvram", RS_UNKNOWN }, { "nvdata", RS_UNKNOWN }, { "nvcfg", RS_UNKNOWN },
	{ "md_sec", RS_UNKNOWN }, { "sec1", RS_UNKNOWN }, { "seccfg", RS_UNKNOWN },
	{ "vbmeta", RS_UNKNOWN }, { "vbmeta_system", RS_UNKNOWN }, { "vbmeta_vendor", RS_UNKNOWN },
	{ "tz", RS_UNKNOWN }, { "hyp", RS_UNKNOWN }, { "keymaster", RS_UNKNOWN }, { "keystore", RS_UNKNOWN },
	{ "storsec", RS_UNKNOWN }, { "secdata", RS_UNKNOWN }, { "ssd", RS_UNKNOWN },
	{ "pvmfw", RS_UNKNOWN }, { "vm-bootsys", RS_UNKNOWN }, { "vm-persist", RS_UNKNOWN },
	{ "imagefv", RS_UNKNOWN }, { "toolsfv", RS_UNKNOWN }, { "tee", RS_UNKNOWN }, { "rotfw", RS_UNKNOWN },
	{ "frp", RS_UNKNOWN }, { "preloader_raw", RS_UNKNOWN }, { "lk", RS_UNKNOWN },
	{ "bootloader1", RS_UNKNOWN }, { "bootloader2", RS_UNKNOWN }, { "ocdt", RS_UNKNOWN },
};
static const size_t core_names_cnt = ARRAY_SIZE(core_names);

/* === 受保护 dev_t 缓存 === */
struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_protected_devs, 7); /* 128 buckets */
static bool bbg_cache_built;

/* === 就绪门控（观察挂载 + Zygote 预执行；只构建一次缓存） === */
static const char * const ready_mounts[] = { "/system", "/vendor", "/product", "/odm", "/data" };
#define READY_MOUNT_CNT (ARRAY_SIZE(ready_mounts))
static atomic_long_t ready_seen_mask = ATOMIC_LONG_INIT(0); /* bit i set when path seen */
static bool bbg_ready; /* latched */

static atomic_t bbg_bprm_built = ATOMIC_INIT(0);
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

/* 小延迟，确保 by-name 符号链接稳定 */
static struct delayed_work bbg_one_shot_build;
static struct workqueue_struct *bbg_wq;
static unsigned int bbg_post_ready_delay_ms = 1200; /* 1.2s */
module_param_named(post_ready_delay_ms, bbg_post_ready_delay_ms, uint, 0644);
MODULE_PARM_DESC(post_ready_delay_ms, "Delay (ms) after readiness before building cache");

/* === 仅按进程名的可信旁路名单 === */
/* 写入旁路：含 rmt_storage */
static const char * const trusted_writer_procs[] = {
	"update_engine",
	"update_engine_sideload",
	"rmt_storage",
};
/* IOCTL 旁路：不含 rmt_storage（避免破坏性 ioctl） */
static const char * const trusted_ioctl_procs[] = {
	"update_engine",
	"update_engine_sideload",
};

static inline bool in_list(const char *comm, const char * const *list, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		if (strncmp(comm, list[i], TASK_COMM_LEN) == 0)
			return true;
	return false;
}

static bool has_ancestor_comm(const char *needle, int max_hops)
{
	struct task_struct *p;
	bool found = false;

	if (!needle || max_hops <= 0)
		return false;

	rcu_read_lock();
	p = current;
	while (p && max_hops-- > 0) {
		if (strncmp(p->comm, needle, TASK_COMM_LEN) == 0) { found = true; break; }
		p = rcu_dereference(p->real_parent);
		if (!p || p->pid <= 1) break;
	}
	rcu_read_unlock();
	return found;
}

static inline bool is_fastbootd_trusted(void)
{
	if (strncmp(current->comm, "fastbootd", TASK_COMM_LEN) == 0)
		return true;
	return has_ancestor_comm("fastbootd", 4);
}

static inline bool is_trusted_writer(void)
{
	return is_fastbootd_trusted() ||
	       in_list(current->comm, trusted_writer_procs, ARRAY_SIZE(trusted_writer_procs));
}

static inline bool is_trusted_ioctl(void)
{
	return is_fastbootd_trusted() ||
	       in_list(current->comm, trusted_ioctl_procs, ARRAY_SIZE(trusted_ioctl_procs));
}

/* === 工具函数 === */
static inline bool bbg_is_ready(void)
{
	unsigned long mask = atomic_long_read(&ready_seen_mask);
	unsigned long full = (READY_MOUNT_CNT >= BITS_PER_LONG) ? ~0UL : ((1UL << READY_MOUNT_CNT) - 1);
	return bbg_ready || ((mask & full) == full);
}

static bool cache_has(dev_t dev)
{
	struct bbg_node *p;
	hash_for_each_possible(bbg_protected_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void cache_add(dev_t dev)
{
	struct bbg_node *n;
	if (!dev || cache_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n) return;
	n->dev = dev;
	hash_add(bbg_protected_devs, &n->h, (u64)dev);
#if BB_VERBOSE
	bb_pr("protect dev %u:%u\n", MAJOR(dev), MINOR(dev));
#endif
}

static bool resolve_byname_dev(const char *name, dev_t *out)
{
	char *path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
	dev_t dev; int ret;
	if (!path) return false;
	ret = lookup_bdev(path, &dev);
	kfree(path);
	if (ret) return false;
	*out = dev;
	return true;
}

/* 一次性构建缓存：尝试原名与 _a/_b 变体 */
static void bbg_build_cache_once(void)
{
	size_t i; dev_t dev; bool any = false;

	if (READ_ONCE(bbg_cache_built))
		return;

	for (i = 0; i < core_names_cnt; i++) {
		const char *n = core_names[i].name; bool ok = false;

		if (resolve_byname_dev(n, &dev)) { cache_add(dev); ok = true; }

		if (!ok) {
			char *na = kasprintf(GFP_KERNEL, "%s_a", n);
			char *nb = kasprintf(GFP_KERNEL, "%s_b", n);
			if (na) { if (resolve_byname_dev(na, &dev)) { cache_add(dev); ok = true; } kfree(na); }
			if (!ok && nb) { if (resolve_byname_dev(nb, &dev)) { cache_add(dev); ok = true; } kfree(nb); }
		}

		core_names[i].st = ok ? RS_OK : RS_FAIL;
		any |= ok;
	}

	WRITE_ONCE(bbg_cache_built, true);
#if BB_VERBOSE
	bb_pr("one-shot cache built (any=%d)\n", any);
#endif
}

/* 观察挂载，触发一次性构建 */
static int bbg_mark_mount_seen(const char *mountpoint)
{
	size_t i;
	if (!mountpoint) return 0;
	for (i = 0; i < READY_MOUNT_CNT; i++) {
		if (strcmp(mountpoint, ready_mounts[i]) == 0) {
			atomic_long_or(1UL << i, &ready_seen_mask);
			return 1;
		}
	}
	return 0;
}

static void bbg_maybe_arm_build(void)
{
	if (bbg_ready || !bbg_wq) return;
	if (bbg_is_ready()) {
		bbg_ready = true;
		schedule_delayed_work(&bbg_one_shot_build, msecs_to_jiffies(bbg_post_ready_delay_ms));
		bb_pr("armed one-shot cache build after readiness\n");
	}
}

static int bbg_sb_mount(const char *dev_name, const struct path *path, const char *type,
		unsigned long flags, void *data)
{
	const char *mp = NULL;
	if (path && path->dentry)
		mp = path->dentry->d_name.name;
	if (bbg_mark_mount_seen(mp))
		bbg_maybe_arm_build();
	return 0; /* 不阻断挂载 */
}

/* Zygote pre-exec：在应用进程起来前，若已就绪则立即构建一次缓存 */
static int bbg_bprm_check_security(struct linux_binprm *bprm)
{
	size_t i; const char *path;
	if (!bprm || !bprm->filename)
		return 0;
	if (atomic_read(&bbg_bprm_built))
		return 0;

	path = bprm->filename;
	for (i = 0; i < ZYGOTE_CAND_CNT; i++) {
		if (strcmp(path, zygote_candidates[i]) == 0) {
			if (bbg_is_ready() && !READ_ONCE(bbg_cache_built))
				bbg_build_cache_once();
			atomic_set(&bbg_bprm_built, 1);
			break;
		}
	}
	return 0;
}

/* === 执法 === */
static int deny(const char *why)
{
	if (!BB_ENFORCING) return 0;
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	return -EPERM;
}

static bool is_destructive_ioctl(unsigned int cmd)
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

/* 在缓存构建前的兜底：反向 by-name 解析，与当前 dev_t 匹配则加入缓存并拒绝 */
static bool reverse_dev_match_and_cache(dev_t cur)
{
	size_t i; dev_t d; bool hit = false;

	for (i = 0; i < core_names_cnt; i++) {
		if (resolve_byname_dev(core_names[i].name, &d) && d == cur) { hit = true; break; }

		/* _a/_b 变体 */
		{
			char *na = kasprintf(GFP_ATOMIC, "%s_a", core_names[i].name);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", core_names[i].name);
			if (na) { if (resolve_byname_dev(na, &d) && d == cur) { kfree(na); kfree(nb); hit = true; break; } kfree(na); }
			if (nb) { if (resolve_byname_dev(nb, &d) && d == cur) { kfree(nb); hit = true; break; } kfree(nb); }
		}
	}
	if (hit) cache_add(cur);
	return hit;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE))  /* 仅对写入路径执法 */
		return 0;
	if (!file)
		return 0;

	/* 纯进程名旁路（静默）：writer 集合 + fastbootd 祖先 */
	if (is_trusted_writer())
		return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode))
		return 0;

	if (cache_has(inode->i_rdev))
		return deny("write to protected partition");

	if (reverse_dev_match_and_cache(inode->i_rdev))
		return deny("write to protected partition (dev match)");

	return 0;
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file)
		return 0;

	/* 纯进程名旁路（静默）：仅对 update_engine* 和 fastbootd 祖先；rmt_storage 不在 ioctl 旁路 */
	if (is_trusted_ioctl())
		return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode))
		return 0;

	if (cache_has(inode->i_rdev) && is_destructive_ioctl(cmd))
		return deny("destructive ioctl on protected partition");

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

/* 延迟任务：只构建一次缓存 */
static void bbg_one_shot_build_worker(struct work_struct *ws)
{
	bbg_build_cache_once();
}

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,             bbg_sb_mount),
	LSM_HOOK_INIT(bprm_check_security,  bbg_bprm_check_security),
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (!bbg_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&bbg_one_shot_build, bbg_one_shot_build_worker);
	bb_pr("init (process-only; one-shot cache; reverse dev match; writer/ioctl scoped; silent bypass)\n");
	return 0;
}

static void __exit bbg_exit(void)
{
	if (bbg_wq) {
		cancel_delayed_work_sync(&bbg_one_shot_build);
		destroy_workqueue(bbg_wq);
	}
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

module_init(bbg_init);
module_exit(bbg_exit);

MODULE_DESCRIPTION("Patch for Q1udaoyu");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");