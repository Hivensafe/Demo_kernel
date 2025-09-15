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

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ========= domain substring whitelist ========= */
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

/* ========= partition allowlist (defer to SELinux) ========= */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ========= slot suffix ========= */
extern char *saved_command_line;
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

/* ========= readiness/arming =========
 * armed==0: no interception (return 0 in hooks)
 * armed==1: start enforcing
 */
static atomic_t bbg_armed = ATOMIC_INIT(0);

static __always_inline bool bbg_is_armed(void)
{
	return unlikely(atomic_read(&bbg_armed) != 0);
}

static __always_inline void bbg_arm_once(const char *reason)
{
	if (atomic_xchg(&bbg_armed, 1) == 0)
		bb_pr("armed after %s\n", reason ? reason : "?");
}

/* ========= resolve by-name -> dev_t ========= */
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

/* ========= allow dev cache ========= */
struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 8);

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

/* ========= deny-seen dev cache ========= */
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

/* ========= reverse allow (first-hit) ========= */
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
static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ========= SELinux enforcing (weak symbols) ========= */
#ifdef CONFIG_SECURITY_SELINUX
extern int selinux_enabled __attribute__((weak));
extern int selinux_enforcing __attribute__((weak));
#endif
static __always_inline bool selinux_is_enforcing_now(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	if (&selinux_enabled && !READ_ONCE(selinux_enabled))
		return false;
	if (&selinux_enforcing)
		return READ_ONCE(selinux_enforcing) != 0;
	return false;
#else
	return false;
#endif
}

/* ========= current domain substring match ========= */
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

/* ========= logging throttle ========= */
static unsigned int quiet_boot_ms = 10000; /* still keep for post-armed early window */
module_param(quiet_boot_ms, uint, 0644);
MODULE_PARM_DESC(quiet_boot_ms, "Suppress deny logs during early post-armed window (ms)");

static unsigned int per_dev_log_limit = 1;
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
	p->dev = dev; p->cnt = 1;
	hash_add(denied_logged, &p->h, (u64)dev);
	return true;
}

/* ========= cmdline pack (for log) ========= */
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
static __cold noinline void bbg_log_deny_detail(const char *why, unsigned int cmd_opt)
{
	const int CMD_BUFLEN = 256;
	char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
	if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt)
		pr_info_ratelimited("baseband_guard: deny %s cmd=0x%x argv=\"%s\"\n",
				    why, cmd_opt, cmdbuf ? cmdbuf : "?");
	else
		pr_info_ratelimited("baseband_guard: deny %s argv=\"%s\"\n",
				    why, cmdbuf ? cmdbuf : "?");
	kfree(cmdbuf);
}
static __cold noinline int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;
	if (quiet_boot_ms &&
	    time_before(jiffies, bbg_boot_jiffies + msecs_to_jiffies(quiet_boot_ms)))
		return -EPERM;
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

/* ========= enforcement hooks ========= */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	/* Not armed: do nothing (boot-safe) */
	if (likely(!bbg_is_armed()))
		return 0;

	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	rdev = inode->i_rdev;

	/* Enforcing + domain whitelist → defer to SELinux */
	if (unlikely(selinux_is_enforcing_now() && current_domain_allowed_fast()))
		return 0;

	/* Partition allowlist → defer to SELinux */
	if (likely(allow_has(rdev)))
		return 0;

	/* First-hit reverse allow */
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

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

	/* Not armed: do nothing */
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

/* ========= mount readiness: arm on /data mount ========= */
static int bb_sb_mount(const char *dev_name, const struct path *path,
		       const char *type, unsigned long flags, void *data)
{
	/* 粗判：mount 点名为 "data"（根目录下的 /data），足以触发 arming */
	if (path && path->dentry) {
		const char *bn = path->dentry->d_name.name;
		if (bn && strcmp(bn, "data") == 0)
			bbg_arm_once("/data mount");
	}
	return 0;
}

/* ========= zygote pre-exec guard: arm before apps ========= */
static const char *zygote_candidates[] = {
	"/system/bin/app_process64",
	"/system/bin/app_process32",
	"/apex/com.android.art/bin/app_process64",
	"/apex/com.android.art/bin/app_process32",
};
#define ZYGOTE_CAND_CNT (ARRAY_SIZE(zygote_candidates))

static int bb_bprm_check_security(struct linux_binprm *bprm)
{
	size_t i;
	const char *path;

	if (!bprm || !bprm->filename)
		return 0;
	if (bbg_is_armed())
		return 0;

	path = bprm->filename;
	for (i = 0; i < ZYGOTE_CAND_CNT; i++) {
		if (strcmp(path, zygote_candidates[i]) == 0) {
			bbg_arm_once("zygote pre-exec");
			break;
		}
	}
	return 0;
}

/* ========= file_ioctl_compat on 6.6+ ========= */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ========= LSM registration ========= */
static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,     bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,          bb_file_ioctl),
#ifdef BB_HAVE_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,   bb_file_ioctl_compat),
#endif
	LSM_HOOK_INIT(sb_mount,            bb_sb_mount),
	LSM_HOOK_INIT(bprm_check_security, bb_bprm_check_security),
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_boot_jiffies = jiffies;
	bbg_slot_suffix  = slot_suffix_from_cmdline_once();
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("baseband_guard power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");