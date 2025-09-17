// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_all (gated) — Only arm AFTER:
 *   - /data is precisely mounted (mountpoint == "/data"), AND
 *   - (SELinux is Enforcing OR zygote has started).
 *
 * Before armed: no interception, no logs.
 *
 * Then: Block ALL partition writes by default; for allowlisted procs/partitions,
 *       when SELinux is Enforcing, defer to SELinux (do not pre-allow).
 *       First-write dev_t reverse match cache for allowlist.
 *
 * Works on 5.10, 5.15, 6.1, 6.6. No build-time hard deps on SELinux symbols.
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
#include <linux/dcache.h>    /* d_path */
#include <linux/uaccess.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ===== Process SELinux domain whitelist (substring match) ===== */
static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"oplus",
	"oppo",
	"feature",
	"swap",
	"system_perf_init",
	"hal_bootctl_default",
	"fsck",
	"vendor_qti",
	"mi_ric",
};
static const size_t allowed_domain_substrings_cnt =
	ARRAY_SIZE(allowed_domain_substrings);

/* ===== Partition allowlist (defer-to-SELinux if matched) ===== */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== Slot suffix (computed once) ===== */
extern char *saved_command_line; /* from init/main.c */
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

/* ===== by-name -> dev_t (works on 5.10~6.6; no lookup_bdev proto reliance) ===== */
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

/* ===== Allowed dev_t cache ===== */
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

/* ===== Deny-seen dev_t cache ===== */
struct seen_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(denied_seen, 8); /* 256 buckets */

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

/* ===== Is this dev_t an allowlisted partition? (with slot suffix variants) ===== */
static __always_inline bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i;
	dev_t dev;

	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];
		bool ok = false;

		if (resolve_byname_dev(n, &dev) && dev == cur)
			return true;

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

/* ===== First-write reverse match & cache ===== */
static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== SELinux enforcing probe (weak symbols; no link-time hard dep) ===== */
#ifdef CONFIG_SECURITY_SELINUX
extern int selinux_enabled __attribute__((weak));
extern int selinux_enforcing __attribute__((weak));
#endif

static __always_inline bool selinux_is_enforcing_now(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	/* weak symbol may be NULL if not exported */
	if (&selinux_enabled && !READ_ONCE(selinux_enabled))
		return false;
	if (&selinux_enforcing)
		return READ_ONCE(selinux_enforcing) != 0;
	return false;
#else
	return false;
#endif
}

/* ===== current domain substring match (cache last sid) ===== */
#ifdef CONFIG_SECURITY_SELINUX
static u32 sid_cache_last;
static bool sid_cache_last_ok;
#endif

static __always_inline bool current_domain_allowed_fast(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	bool ok = false;
	size_t i;
	char *ctx = NULL;
	u32 len = 0;

	security_cred_getsecid(current_cred(), &sid);

	if (sid && sid == sid_cache_last)
		return sid_cache_last_ok;

	if (sid && !security_secid_to_secctx(sid, &ctx, &len) && ctx && len) {
		for (i = 0; i < allowed_domain_substrings_cnt; i++) {
			const char *needle = allowed_domain_substrings[i];
			if (needle && *needle && strnstr(ctx, needle, len)) { ok = true; break; }
		}
	}
	if (ctx) security_release_secctx((char *)ctx, len);

	sid_cache_last = sid;
	sid_cache_last_ok = ok;
	return ok;
#else
	return false;
#endif
}

/* ===== ARMING GATE: /data mounted && (SELinux Enforcing || zygote started) ===== */
static bool bbg_data_mounted;
static bool bbg_zygote_seen;

static __always_inline bool bbg_is_armed(void)
{
	/* Only arm when /data is mounted AND (selinux enforcing OR zygote started) */
	return likely(bbg_data_mounted) &&
	       (unlikely(bbg_zygote_seen) || unlikely(selinux_is_enforcing_now()));
}

/* mount hook: detect exact "/data" mount */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bbg_sb_mount(const char *dev_name, const struct path *path,
			const char *type, unsigned long flags, void *data)
#else
static int bbg_sb_mount(const char *dev_name, struct path *path,
			const char *type, unsigned long flags, void *data)
#endif
{
	if (!bbg_data_mounted && path) {
		char *buf = (char*)__get_free_page(GFP_ATOMIC);
		if (buf) {
			char *p = d_path(path, buf, PAGE_SIZE);
			if (!IS_ERR(p) && strcmp(p, "/data") == 0) {
				bbg_data_mounted = true;
#if BB_VERBOSE
				bb_pr("mark data_mounted\n");
#endif
			}
			free_page((unsigned long)buf);
		}
	}
	return 0; /* allow all mounts */
}

/* zygote pre-exec detect */
static int bbg_bprm_check_security(struct linux_binprm *bprm)
{
	static const char * const zygote_candidates[] = {
		"/system/bin/app_process64",
		"/system/bin/app_process32",
		"/apex/com.android.art/bin/app_process64",
		"/apex/com.android.art/bin/app_process32",
	};
	size_t i;
	const char *path;

	if (bbg_zygote_seen) return 0;
	if (!bprm || !bprm->filename) return 0;

	path = bprm->filename;
	for (i = 0; i < ARRAY_SIZE(zygote_candidates); i++) {
		if (strcmp(path, zygote_candidates[i]) == 0) {
			bbg_zygote_seen = true;
#if BB_VERBOSE
			bb_pr("zygote seen\n");
#endif
			break;
		}
	}
	return 0;
}

/* ===== Logging throttles ===== */
static unsigned int quiet_boot_ms = 10000; /* early boot quiet */
module_param(quiet_boot_ms, uint, 0644);
MODULE_PARM_DESC(quiet_boot_ms, "Suppress deny logs during early boot window (ms)");

static unsigned int per_dev_log_limit = 1; /* max logs per dev this boot */
module_param(per_dev_log_limit, uint, 0644);
MODULE_PARM_DESC(per_dev_log_limit, "Max deny logs per block dev_t this boot");

static unsigned long bbg_boot_jiffies;

/* per-dev log counter */
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

/* ===== Helpers (cold path) ===== */
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

/* only argv in logs; no path, no selinux ctx */
static __cold noinline void bbg_log_deny_detail(const char *why, unsigned int cmd_opt)
{
	const int CMD_BUFLEN = 256;
	char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info_ratelimited("baseband_guard: deny %s cmd=0x%x argv=\"%s\"\n",
				    why, cmd_opt, cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited("baseband_guard: deny %s argv=\"%s\"\n",
				    why, cmdbuf ? cmdbuf : "?");
	}
	kfree(cmdbuf);
}

static __cold noinline int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;

	/* early boot silent window (after armed still apply) */
	if (quiet_boot_ms &&
	    time_before(jiffies, bbg_boot_jiffies + msecs_to_jiffies(quiet_boot_ms)))
		return -EPERM;

	/* per-dev log limiting */
	if (file) {
		struct inode *inode = file_inode(file);
		if (inode && S_ISBLK(inode->i_mode)) {
			dev_t dev = inode->i_rdev;
			if (!bbg_should_log(dev))
				return -EPERM;
		}
	}

	bbg_log_deny_detail(why, cmd_opt);
	return -EPERM;
}

/* ===== Enforcement hooks ===== */

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	/* Not armed yet => do nothing */
	if (likely(!bbg_is_armed()))
		return 0;

	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	rdev = inode->i_rdev;

	/* 仅在 Enforcing 且域命中时，放行并交给 SELinux */
	if (unlikely(selinux_is_enforcing_now() && current_domain_allowed_fast()))
		return 0;

	/* 分区白名单命中 → defer to SELinux */
	if (likely(allow_has(rdev)))
		return 0;

	/* 首次遇到该 dev：尝试反查命中白名单则缓存并 defer */
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	/* miss：记忆并拒绝 */
	denied_seen_add(rdev);
	return deny("write to protected partition", file, 0);
}

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

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	dev_t rdev;

	/* Not armed yet => do nothing */
	if (likely(!bbg_is_armed()))
		return 0;

	if (unlikely(!file)) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(!is_destructive_ioctl(cmd)))
		return 0;

	rdev = inode->i_rdev;

	if (unlikely(selinux_is_enforcing_now() && current_domain_allowed_fast()))
		return 0;

	if (likely(allow_has(rdev)))
		return 0;

	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	denied_seen_add(rdev);
	return deny("destructive ioctl on protected partition", file, cmd);
}

/* 6.6+ has file_ioctl_compat; 5.10/5.15/6.1 may not */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ===== LSM registration ===== */
static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#ifdef BB_HAVE_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,             bbg_sb_mount),
	LSM_HOOK_INIT(bprm_check_security,  bbg_bprm_check_security),
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_slot_suffix = slot_suffix_from_cmdline_once();
	bbg_boot_jiffies = jiffies;
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("All-partition write guard, ARMED after /data mounted & (SELinux Enforcing or zygote started)");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");