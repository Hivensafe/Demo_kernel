// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_selinux_gate_all:
 *
 * 实现：
 *   - 保护所有 by-name 分区，唯独 boot/init_boot/dtbo/vendor_boot（含 _a/_b）不受保护。
 *   - 仅 SELinux 域为 "u:r:update_engine:s0" 或 "u:r:fastbootd:s0" 或"u:r:recovery:s0"的进程可修改受保护分区；
 *     其它任意域对受保护分区的写入与破坏性块设备 ioctl 一律拒绝。
 *
 * 关键特性：
 *   - 严格依赖 SELinux 域（security_cred_getsecid + security_secid_to_secctx），不看进程名/祖先/cmdline。
 *   - 构建一次“允许集”（仅包含四个不保护分区的 dev_t），其余全部视为受保护。
 *   - 构建前的首写兜底：遇到某 dev_t，若解析命中四个不保护名之一，则即时加入允许集并放行；否则按受保护处理。
 *   - 安静：旁路不打印日志；仅拒绝时 rate-limited 打一条。
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/binfmts.h>   /* struct linux_binprm */
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


static const char * const allowed_selinux_domains[] = {
	"u:r:update_engine:s0",
	"u:r:update_engine_sideload:s0",
	"u:r:fastbootd:s0",
	"u:r:recovery:s0",
	"u:r:vendor_rmt_storage:s0",
};
static const size_t allowed_domains_cnt = ARRAY_SIZE(allowed_selinux_domains);

/* 唯一“不受保护”的 by-name 名称（含 _a/_b 变体） */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
};
static const size_t allowlist_names_cnt = ARRAY_SIZE(allowlist_names);

/* 允许 dev_t 集合（只有四个不保护分区加入这里） */
struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_allow_devs, 6); /* 64 buckets 足够 */
static bool bbg_cache_built;

/* 挂载就绪门控（只构建一次允许集） */
static const char * const ready_mounts[] = { "/system", "/data" };
#define READY_MOUNT_CNT (ARRAY_SIZE(ready_mounts))
static atomic_long_t ready_seen_mask = ATOMIC_LONG_INIT(0);
static bool bbg_ready;

static atomic_t bbg_bprm_built = ATOMIC_INIT(0);
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

/* 小延迟，确保 by-name 稳定 */
static struct delayed_work bbg_one_shot_build;
static struct workqueue_struct *bbg_wq;
static unsigned int bbg_post_ready_delay_ms = 1200;
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

/* 允许集：仅四个名字及其 _a/_b 变体 */
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

/* 反向匹配兜底：若当前 dev_t 等于四个名字之一（含 _a/_b），则加入允许集并返回 true */
static bool reverse_allow_match_and_cache(dev_t cur)
{
	size_t i; dev_t d;

	for (i = 0; i < allowlist_names_cnt; i++) {
		const char *n = allowlist_names[i];

		if (resolve_byname_dev(n, &d) && d == cur) { allow_add(cur); return true; }

		/* _a/_b 变体 */
		{
			char *na = kasprintf(GFP_ATOMIC, "%s_a", n);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", n);
			if (na) { if (resolve_byname_dev(na, &d) && d == cur) { kfree(na); kfree(nb); allow_add(cur); return true; } kfree(na); }
			if (nb) { if (resolve_byname_dev(nb, &d) && d == cur) { kfree(nb); allow_add(cur); return true; } kfree(nb); }
		}
	}
	return false;
}

/* mount 观察：标记就绪并武装一次性构建 */
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

/* Zygote pre-exec：在应用前尽早完成一次构建 */
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

/* SELinux 域判定（精确字符串匹配） */
static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	bool ok = false;
	size_t i;

	security_cred_getsecid(current_cred(), &sid);
	if (!sid)
		return false;

	if (security_secid_to_secctx(sid,&ctx, &len))
		return false;
	if (!ctx || !len)
		goto out;

	for (i = 0; i < allowed_domains_cnt; i++) {
		if (len == strlen(allowed_selinux_domains[i]) &&
		    !strncmp(ctx, allowed_selinux_domains[i], len)) {
			ok = true; break;
		}
	}
out:
	security_release_secctx(ctx, len);
	return ok;
#else
	/* 若未启用 SELinux，为安全默认“不允许”。需要放开可改为 return true; */
	return false;
#endif
}

static int deny(const char *why)
{
	if (!BB_ENFORCING) return 0;
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	return -EPERM;
}

/* 认为“破坏性”的块设备 ioctl 集 */
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

/* ===== 执法点 ===== */

/* 写入：若命中允许集（四个不保护分区）则直接放行；否则仅允许“允许域”，其余拒绝 */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE))
		return 0;
	if (!file)
		return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode))
		return 0;

	/* 先看是否属于四个不保护分区（允许集）；构建前用反向匹配兜底 */
	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0; /* 不保护：直接放行 */

	/* 其余一切分区 = 受保护：仅允许“允许域” */
	if (current_domain_allowed())
		return 0;

	return deny("write to protected partition");
}

/* 破坏性 ioctl：不保护分区放行；受保护分区仅允许“允许域” */
static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file)
		return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode))
		return 0;

	/* 不保护分区：直接放行 */
	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	/* 受保护分区：仅允许“允许域”执行破坏性 ioctl；其它域拒绝 */
	if (is_destructive_ioctl(cmd) && !current_domain_allowed())
		return deny("destructive ioctl on protected partition");

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

/* 延迟一次性构建 */
static void bbg_one_shot_build_worker(struct work_struct *ws)
{
	bbg_build_allowlist_once();
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
	bb_pr("init (SELinux-domain gate; protect all except boot/init_boot/dtbo/vendor_boot; quiet)\n");
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

MODULE_DESCRIPTION("SELinux-domain gated LSM: protect ALL by-name partitions except boot/init_boot/dtbo/vendor_boot");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");