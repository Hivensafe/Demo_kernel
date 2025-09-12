// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_selinux_substr_gate (no reverse-match)
 *
 * 要求实现：
 *  - 不做首写反查兜底（no reverse dev_t match）。只依赖一次性 allowlist（boot/init_boot/dtbo/vendor_boot）。
 *  - 命中“放行列表”（分区 allowlist 或 进程允许域）后仅 return 0，由 SELinux 继续处理。
 *  - 保护范围：除 allowlist 四类分区外的所有 by-name 分区（写入 + 破坏性 ioctl 一律拦）。
 *  - 进程放行：SELinux 域字符串包含任一关键子串（update_engine / fastbootd / recovery / rmt_storage）。
 *  - 一次性构建：观察 /system 与 /data 挂载 → 延迟 1.2s → 构建一次；无轮询、无重试。
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
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/param.h>
#include <linux/sched.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ===== 允许的 SELinux 域 —— 子串匹配（模糊） =====
 *   "update_engine"  → 匹配 u:r:update_engine:s0 / u:r:update_engine_sideload:s0(:c…)
 *   "fastbootd"      → 匹配 u:r:fastbootd:s0(:c…)
 *   "recovery"       → 匹配 u:r:recovery:s0(:c…)
 *   "rmt_storage"    → 匹配 u:r:rmt_storage:s0 / u:r:vendor_rmt_storage:s0(:c…)
 */
static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"oplus",
	"oppo",
	"feature",
	"swap",
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

/* ===== 不受保护的分区名（仅这四类 + _a/_b 变体） ===== */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot","userdata","metadata","cache","misc",
};
static const size_t allowlist_names_cnt = ARRAY_SIZE(allowlist_names);

/* ===== dev_t 允许集（只放四个不受保护分区） ===== */
struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_allow_devs, 6); /* 64 buckets */
static bool bbg_cache_built;

/* ===== 就绪门控：仅观察 /system 与 /data 挂载 ===== */
static const char * const ready_mounts[] = { "/system", "/data" };
#define READY_MOUNT_CNT (ARRAY_SIZE(ready_mounts))
static atomic_long_t ready_seen_mask = ATOMIC_LONG_INIT(0);
static bool bbg_ready;

/* Zygote 前置构建（确保在 app 前尽早构建一次） */
static atomic_t bbg_bprm_built = ATOMIC_INIT(0);
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

/* 一次性延迟任务 */
static struct delayed_work bbg_one_shot_build;
static struct workqueue_struct *bbg_wq;
static unsigned int bbg_post_ready_delay_ms = 1200; /* 1.2s */
module_param_named(post_ready_delay_ms, bbg_post_ready_delay_ms, uint, 0644);
MODULE_PARM_DESC(post_ready_delay_ms, "Delay (ms) after readiness before building allowlist");

/* ===== 工具函数 ===== */
static inline bool bbg_is_ready(void)
{
	unsigned long mask = atomic_long_read(&ready_seen_mask);
	unsigned long full = (READY_MOUNT_CNT >= BITS_PER_LONG) ? ~0UL : ((1UL << READY_MOUNT_CNT) - 1);
	return bbg_ready || ((mask & full) == full);
}

static bool allow_has(dev_t dev)
{
	struct bbg_node *p;
	hash_for_each_possible(bbg_allow_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
{
	struct bbg_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n) return;
	n->dev = dev;
	hash_add(bbg_allow_devs, &n->h, (u64)dev);
#if BB_VERBOSE
	bb_pr("allow dev %u:%u\n", MAJOR(dev), MINOR(dev));
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

/* 构建允许集：仅四个不受保护分区名 + _a/_b 变体 */
static void bbg_build_allowlist_once(void)
{
	size_t i; dev_t dev; bool any = false;

	if (READ_ONCE(bbg_cache_built))
		return;

	for (i = 0; i < allowlist_names_cnt; i++) {
		const char *n = allowlist_names[i]; bool ok = false;

		if (resolve_byname_dev(n, &dev)) { allow_add(dev); ok = true; }

		if (!ok) {
			char *na = kasprintf(GFP_KERNEL, "%s_a", n);
			char *nb = kasprintf(GFP_KERNEL, "%s_b", n);
			if (na) { if (resolve_byname_dev(na, &dev)) { allow_add(dev); ok = true; } kfree(na); }
			if (!ok && nb) { if (resolve_byname_dev(nb, &dev)) { allow_add(dev); ok = true; } kfree(nb); }
		}
		any |= ok;
	}

	WRITE_ONCE(bbg_cache_built, true);
#if BB_VERBOSE
	bb_pr("allowlist built (any=%d)\n", any);
#endif
}

/* 观察 mount，就绪后武装一次性构建 */
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
		bb_pr("armed one-shot allowlist build after readiness\n");
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
	return 0; /* 允许 mount */
}

/* Zygote pre-exec：尽早完成一次构建 */
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
				bbg_build_allowlist_once();
			atomic_set(&bbg_bprm_built, 1);
			break;
		}
	}
	return 0;
}

/* 读取当前进程 SELinux 域，并与“子串白名单”匹配（模糊） */
static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;  /* 非 const，便于 security_release_secctx() 释放 */
	u32 len = 0;
	bool ok = false;
	size_t i;

	/* 6.6：从 cred 获取 secid */
	security_cred_getsecid(current_cred(), &sid);
	if (!sid)
		return false;

	if (security_secid_to_secctx(sid, &ctx, &len))
		return false;

	if (!ctx || !len)
		goto out;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle) {
			if (strnstr(ctx, needle, len)) { ok = true; break; }
		}
	}
out:
	security_release_secctx(ctx, len);
	return ok;
#else
	/* 未启用 SELinux 时，默认不允许（更安全） */
	return false;
#endif
}

/* ===== 执法点 ===== */

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

/* 写入：满足任一放行条件 → 交给 SELinux；否则拒绝 */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	/* 任一豁免：放行，交由 SELinux 继续处理 */
	{
		bool is_partition_exempt = allow_has(inode->i_rdev);
		bool is_process_exempt   = current_domain_allowed();
		if (is_partition_exempt || is_process_exempt)
			return 0;
	}

	/* 唯一拒绝：非豁免进程写非豁免（受保护）分区 */
	return deny("write to protected partition by_Q1udaoyu");
}

/* 破坏性 ioctl：同上 */
static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0; /* 非破坏性 ioctl 不拦 */

	{
		bool is_partition_exempt = allow_has(inode->i_rdev);
		bool is_process_exempt   = current_domain_allowed();
		if (is_partition_exempt || is_process_exempt)
			return 0; /* 放行 → 交给 SELinux */
	}

	return deny("destructive ioctl on protected partition");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

/* 一次性构建 worker */
static void bbg_one_shot_build_worker(struct work_struct *ws)
{
	bbg_build_allowlist_once();
}

/* 钩子表 */
static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,             bbg_sb_mount),
	LSM_HOOK_INIT(bprm_check_security,  bbg_bprm_check_security),
};

/* LSM 初始化/退出 */
static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (!bbg_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&bbg_one_shot_build, bbg_one_shot_build_worker);
	bb_pr("init (no-reverse; SELinux-substr gate; power by https://t.me/qdykernel)\n");
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

MODULE_DESCRIPTION("power by https://t.me/qdykernel");
MODULE_AUTHOR("秋刀鱼&https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");