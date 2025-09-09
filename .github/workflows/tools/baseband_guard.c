// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_autogate: LSM to deny writes to critical baseband/bootloader partitions
 *
 * One-button behavior:
 *  - Zero retries/loops. Build dev_t cache EXACTLY ONCE when the device is logically ready
 *    (core Android mounts observed) and strictly before any apps can run (zygote pre-exec).
 *  - Reverse dev_t match remains active even before cache is built, to block first write.
 *  - Quiet logs (rate-limited info; verbose via Kconfig).
 *
 * This variant WHITELISTS rmt_storage & update_engine family with SILENT bypass.
 *
 * Linux 6.6 API assumptions:
 *  - lookup_bdev(const char *path, dev_t *dev)
 *  - LSM hooks: file_permission, file_ioctl, file_ioctl_compat(>=6.6), sb_mount, bprm_check_security
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

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_ALLOW_IN_RECOVERY
#define BB_ALLOW_IN_RECOVERY 1
#else
#define BB_ALLOW_IN_RECOVERY 0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

extern char *saved_command_line; /* from init/main.c */

struct name_entry { const char *name; u8 st; };
enum res_state { RS_UNKNOWN = 0, RS_OK = 1, RS_FAIL = 2 };

/* === Protected partition names (customize as needed) === */
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

/* === Protected dev_t cache === */
struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_protected_devs, 7); /* 128 buckets */
static bool bbg_cache_built;

/* === Readiness gating (observe mounts, then build once; also gate on zygote pre-exec) === */
static const char * const ready_mounts[] = { "/system", "/vendor", "/product", "/odm", "/data" };
#define READY_MOUNT_CNT (ARRAY_SIZE(ready_mounts))
static atomic_long_t ready_seen_mask = ATOMIC_LONG_INIT(0); /* bit i set when path seen */
static bool bbg_ready; /* latched */

/* Zygote pre-exec guard */
static atomic_t bbg_bprm_built = ATOMIC_INIT(0);
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

/* Optional: tiny post-ready delay to allow by-name symlinks to settle */
static struct delayed_work bbg_one_shot_build;
static struct workqueue_struct *bbg_wq;
static unsigned int bbg_post_ready_delay_ms = 1200; /* 1.2s */
module_param_named(post_ready_delay_ms, bbg_post_ready_delay_ms, uint, 0644);
MODULE_PARM_DESC(post_ready_delay_ms, "Delay (ms) after readiness before building cache");

/* === Trusted process allowlist (full bypass; SILENT) === */
static const char * const trusted_procs[] = {
	"rmt_storage",
	"update_engine",
	"update_engine_sideload",
	"updata_engien", /* 兼容笔误 */
};
static inline bool is_trusted_proc(void)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(trusted_procs); i++) {
		if (strcmp(current->comm, trusted_procs[i]) == 0)
			return true;
	}
	return false;
}

/* === Helpers === */
static const char *slot_suffix_from_cmdline(void)
{
	const char *p = saved_command_line;
	if (!p) return NULL;
	p = strstr(p, "androidboot.slot_suffix=");
	if (!p) return NULL;
	p += strlen("androidboot.slot_suffix=");
	if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b')) return (p[1] == 'a') ? "_a" : "_b";
	return NULL;
}

static bool in_recovery_mode(void)
{
#if BB_ALLOW_IN_RECOVERY
	if (!saved_command_line) return false;
	if (strstr(saved_command_line, "androidboot.mode=recovery")) return true;
#endif
	return false;
}

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

/* === One-shot cache build === */
static void bbg_build_cache_once(void)
{
	const char *suf = slot_suffix_from_cmdline();
	size_t i; dev_t dev; bool any = false;

	if (READ_ONCE(bbg_cache_built))
		return;

	for (i = 0; i < core_names_cnt; i++) {
		const char *n = core_names[i].name; bool ok = false;
		if (resolve_byname_dev(n, &dev)) { cache_add(dev); ok = true; }
		if (!ok && suf) {
			char *nm = kasprintf(GFP_KERNEL, "%s%s", n, suf);
			if (nm) { if (resolve_byname_dev(nm, &dev)) { cache_add(dev); ok = true; } kfree(nm); }
		}
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

static void bbg_one_shot_build_worker(struct work_struct *ws)
{
	bbg_build_cache_once();
}

/* === Readiness detection via mount events === */
static void bbg_maybe_arm_build(void)
{
	if (bbg_ready || !bbg_wq)
		return;
	if (bbg_is_ready()) {
		bbg_ready = true;
		schedule_delayed_work(&bbg_one_shot_build, msecs_to_jiffies(bbg_post_ready_delay_ms));
		bb_pr("armed one-shot cache build after readiness\n");
	}
}

static int bbg_mark_mount_seen(const char *mountpoint)
{
	size_t i;
	if (!mountpoint)
		return 0;
	for (i = 0; i < READY_MOUNT_CNT; i++) {
		if (strcmp(mountpoint, ready_mounts[i]) == 0) {
			atomic_long_or(1UL << i, &ready_seen_mask);
			return 1;
		}
	}
	return 0;
}

static int bbg_sb_mount(const char *dev_name, const struct path *path, const char *type,
		unsigned long flags, void *data)
{
	const char *mp = NULL;
	if (path && path->dentry)
		mp = path->dentry->d_name.name;
	if (bbg_mark_mount_seen(mp))
		bbg_maybe_arm_build();
	return 0; /* allow all mounts */
}

/* === Zygote pre-exec guard === */
static int bbg_bprm_check_security(struct linux_binprm *bprm)
{
	size_t i; const char *path;
	if (!bprm || !bprm->filename)
		return 0;
	if (atomic_read(&bbg_bprm_built))
		return 0;
	path = bprm->filename;
	for (i = 0; i < ARRAY_SIZE(zygote_candidates); i++) {
		if (strcmp(path, zygote_candidates[i]) == 0) {
			/* If logically ready but cache not built, force immediate build. */
			if (bbg_is_ready() && !READ_ONCE(bbg_cache_built))
				bbg_build_cache_once();
			atomic_set(&bbg_bprm_built, 1);
			break;
		}
	}
	return 0;
}

/* === Enforcement === */
static int deny(const char *why)
{
	if (!BB_ENFORCING) return 0;
	if (BB_ALLOW_IN_RECOVERY && in_recovery_mode()) return 0;
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

/* Reverse dev_t match as a safety net even before cache is built; no retries */
static bool reverse_dev_match_and_cache(dev_t cur)
{
	size_t i; dev_t d; bool hit = false; const char *suf = slot_suffix_from_cmdline();

	for (i = 0; i < core_names_cnt; i++) {
		if (resolve_byname_dev(core_names[i].name, &d) && d == cur) { hit = true; break; }
		if (suf) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", core_names[i].name, suf);
			if (nm) { if (resolve_byname_dev(nm, &d) && d == cur) { kfree(nm); hit = true; break; } kfree(nm); }
		} else {
			char *na = kasprintf(GFP_ATOMIC, "%s_a", core_names[i].name);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", core_names[i].name);
			if (na) { if (resolve_byname_dev(na, &d) && d == cur) { kfree(na); kfree(nb); hit = true; break; } kfree(na); }
			if (nb) { if (resolve_byname_dev(nb, &d) && d == cur) { kfree(nb); hit = true; break; } kfree(nb); }
		}
	}
	if (hit)
		cache_add(cur);
	return hit;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE))
		return 0;
	if (!file)
		return 0;

	/* ===== Full bypass for trusted processes (silent) ===== */
	if (is_trusted_proc())
		return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode))
		return 0;

	if (cache_has(inode->i_rdev))
		return deny("write to protected partition");

	/* Safety: even before cache build, try one-shot reverse match for this dev */
	if (reverse_dev_match_and_cache(inode->i_rdev))
		return deny("write to protected partition (dev match)");

	return 0;
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file)
		return 0;

	/* ===== Full bypass for trusted processes (including destructive ioctls) — silent ===== */
	if (is_trusted_proc())
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

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission, bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,      bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,        bbg_sb_mount),
	LSM_HOOK_INIT(bprm_check_security, bbg_bprm_check_security),
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (!bbg_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&bbg_one_shot_build, bbg_one_shot_build_worker);
	bb_pr("init (auto-gated one-shot cache; no retry; pre-app zygote guard; trusted-proc silent bypass)\n");
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

MODULE_DESCRIPTION("Auto-gated no-retry LSM: one-shot cache after core mounts, forced before Zygote exec, with trusted-proc SILENT bypass");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");
