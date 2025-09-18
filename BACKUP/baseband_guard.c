// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard: block writes to block devices unless explicitly allowed.
 * Logging-heavy (no rate limit) build for diagnostics:
 *  - every deny prints: enforcing flag, SELinux domain, argv
 *  - defer to SELinux for allowed domains/partitions (we do NOT pre-allow)
 *  - compatible with 5.10/5.15/6.1/6.6 (uses kern_path to resolve dev_t)
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

/* ====== CONFIG ====== */

#define BB_BYNAME_DIR "/dev/block/by-name"

/* 允许放行的“进程域”子串（命中后**交由 SELinux 决定**，我们不提前投放行票） */
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

/* 允许交给 SELinux 裁决的“分区名”（含 slot 变体）；其余全部拦截 */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ====== Slot suffix（只读一次） ====== */
extern char *saved_command_line; /* from init/main.c */
static const char *bbg_slot_suffix;

static const char *slot_suffix_from_cmdline_once(void)
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

/* ====== by-name -> dev_t（统一实现，兼容 5.10~6.6） ====== */
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

/* ====== allow dev_t cache ====== */
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

/* ====== denied-seen dev_t（避免重复反查）====== */
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

/* ====== 白名单分区反查（含 slot/_a/_b）====== */
static bool is_allowed_partition_dev_resolve(dev_t cur)
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

/* ====== SELinux enforcing & domain ====== */
/* 采用弱符号 + Kconfig 双护栏；未启用 SELinux 时返回 false，不会链接失败 */
#ifdef CONFIG_SECURITY_SELINUX
extern int selinux_enforcing __attribute__((weak));
extern int selinux_enabled  __attribute__((weak));
#endif

static __always_inline bool selinux_is_enforcing_now(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	if (&selinux_enabled && READ_ONCE(selinux_enabled) == 0)
		return false;
	if (&selinux_enforcing)
		return READ_ONCE(selinux_enforcing) != 0;
#endif
	return false;
}

#ifdef CONFIG_SECURITY_SELINUX
static __always_inline bool current_domain_str(char **out_ctx, u32 *out_len)
{
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;

	if (!out_ctx || !out_len) return false;

	security_cred_getsecid(current_cred(), &sid);
	if (!sid) return false;

	if (security_secid_to_secctx(sid, &ctx, &len))
		return false;

	if (!ctx || !len) {
		if (ctx) security_release_secctx((char *)ctx, len);
		return false;
	}

	*out_ctx = ctx;
	*out_len = len;
	return true;
}
#else
static __always_inline bool current_domain_str(char **out_ctx, u32 *out_len)
{
	(void)out_ctx; (void)out_len;
	return false;
}
#endif

static __always_inline bool current_domain_allowed_fast(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 len = 0;
	char *ctx = NULL;
	bool ok = false;
	size_t i;

	if (!selinux_is_enforcing_now())
		return false;

	if (!current_domain_str(&ctx, &len))
		return false;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle && strnstr(ctx, needle, len)) { ok = true; break; }
	}
	security_release_secctx((char *)ctx, len);
	return ok;
#else
	return false;
#endif
}

/* ====== 工具：抓 argv、打印详细日志（无任何限流）====== */
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

static __cold noinline void bbg_log_deny(const char *why, unsigned int cmd_opt)
{
	const int CMD_BUFLEN = 256;
	char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);
	bool enforcing = selinux_is_enforcing_now();
#ifdef CONFIG_SECURITY_SELINUX
	char *ctx = NULL; u32 len = 0;
#endif

	if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

#ifdef CONFIG_SECURITY_SELINUX
	if (current_domain_str(&ctx, &len)) {
		if (cmd_opt) {
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%.*s\" argv=\"%s\" cmd=0x%x\n",
				why, enforcing, (int)len, ctx, cmdbuf ? cmdbuf : "?", cmd_opt);
		} else {
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%.*s\" argv=\"%s\"\n",
				why, enforcing, (int)len, ctx, cmdbuf ? cmdbuf : "?");
		}
		security_release_secctx((char *)ctx, len);
	} else
#endif
	{
		if (cmd_opt) {
			pr_info("baseband_guard: deny %s (enforcing=%d) argv=\"%s\" cmd=0x%x\n",
				why, enforcing, cmdbuf ? cmdbuf : "?", cmd_opt);
		} else {
			pr_info("baseband_guard: deny %s (enforcing=%d) argv=\"%s\"\n",
				why, enforcing, cmdbuf ? cmdbuf : "?");
		}
	}

	kfree(cmdbuf);
}

static __cold noinline int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	(void)file; /* 我们不再打印 path/disk，按你的要求只打命令与域 */
	if (!BB_ENFORCING) return 0;
	bbg_log_deny(why, cmd_opt);
	return -EPERM;
}

/* ====== 破坏性 ioctl 识别 ====== */
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

/* ====== LSM hooks ====== */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	rdev = inode->i_rdev;

	/* 命中“允许域” → 交给 SELinux（我们不提前放行） */
	if (current_domain_allowed_fast())
		return 0;

	/* 命中“允许分区” → 交给 SELinux（我们不提前放行） */
	if (allow_has(rdev))
		return 0;

	/* 首写遇到该 dev：反查白名单命中则缓存并交给 SELinux */
	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	/* miss：记忆并拒绝 */
	denied_seen_add(rdev);
	return deny("write to protected partition", file, 0);
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	dev_t rdev;

	(void)arg;
	if (!file) return 0;
	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	rdev = inode->i_rdev;

	if (current_domain_allowed_fast())
		return 0;

	if (allow_has(rdev))
		return 0;

	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	denied_seen_add(rdev);
	return deny("destructive ioctl on protected partition", file, cmd);
}

/* 6.6 有 file_ioctl_compat；旧核可能没有 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ====== 注册 ====== */
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
	bbg_slot_suffix = slot_suffix_from_cmdline_once();
	pr_info("baseband_guard (diagnostic log build: every deny prints enforcing/domain/argv)\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("Baseband/boot partitions guard (diagnostic logging build)");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");