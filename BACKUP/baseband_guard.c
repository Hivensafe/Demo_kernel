// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard: block writes to block partitions globally,
 * with SELinux-enforcing-aware domain allow and partition allow-list,
 * plus first-write reverse dev_t cache. Detailed diagnostics enabled.
 *
 * - Gated: do nothing until /data mounted OR zygote spotted (500ms poll).
 * - Enforcing check: use security_getenforce() (works on 5.10~6.6).
 * - Domain allow: substring match; only effective when enforcing==1.
 * - Partition allow-list (userdata/cache/metadata/misc + boot family) -> defer to SELinux.
 * - Reverse allow: first encounter of dev_t, if resolves to allow-list name, cache & defer.
 * - Logs (diagnostic build): every deny prints (enforcing/domain/argv). No rate-limit here.
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
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/param.h>

#define BB_ENFORCING 1
#define BB_BYNAME_DIR "/dev/block/by-name"

#define bb_pr(fmt, ...)    pr_info("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

/* ===== domain allow-list (substring, fuzzy) ===== */
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

/* ===== partition allow-list (defer to SELinux) ===== */
static const char * const allowlist_names[] = {
	/* boot family that you said “free to flash” */
	"boot", "init_boot", "dtbo", "vendor_boot",
	/* usability-critical */
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== slot suffix detection (computed once) ===== */
extern char *saved_command_line; /* from init/main.c if exported */
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

/* ===== resolve by-name -> dev_t (works 5.10~6.6) ===== */
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

/* ===== allow dev_t cache ===== */
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
}

/* ===== deny-seen dev_t cache ===== */
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

/* ===== check if a dev_t belongs to allow-list partitions (with suffixes) ===== */
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

/* ===== first-write reverse allow match & cache ===== */
static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== SELinux enforcing check via standard API ===== */
#if defined(CONFIG_SECURITY_SELINUX)
extern int security_getenforce(void);
static __always_inline bool selinux_is_enforcing_now(void)
{
	return security_getenforce() == 1;
}
#else
static __always_inline bool selinux_is_enforcing_now(void) { return false; }
#endif

/* ===== get current SELinux domain (ctx string) -> substring match ===== */
#if defined(CONFIG_SECURITY_SELINUX)
static u32 sid_cache_last;
static bool sid_cache_last_ok;
#endif

static __always_inline bool current_domain_allowed_fast(bool *out_enforcing, const char **out_ctx)
{
#if defined(CONFIG_SECURITY_SELINUX)
	u32 sid = 0;
	bool ok = false;
	size_t i;
	char *ctx = NULL;
	u32 len = 0;
	int enforcing = selinux_is_enforcing_now() ? 1 : 0;

	if (out_enforcing) *out_enforcing = enforcing;

	security_cred_getsecid(current_cred(), &sid);

	if (sid && sid == sid_cache_last) {
		ok = sid_cache_last_ok;
		if (out_ctx) *out_ctx = NULL;
		return ok;
	}

	if (sid && !security_secid_to_secctx(sid, &ctx, &len) && ctx && len) {
		for (i = 0; i < allowed_domain_substrings_cnt; i++) {
			const char *needle = allowed_domain_substrings[i];
			if (needle && *needle && strnstr(ctx, needle, len)) { ok = true; break; }
		}
	}

	sid_cache_last = sid;
	sid_cache_last_ok = ok;

	if (out_ctx) *out_ctx = ctx ? ctx : NULL;
	return ok;
#else
	if (out_enforcing) *out_enforcing = false;
	if (out_ctx) *out_ctx = NULL;
	return false;
#endif
}

/* ===== diagnostics: capture argv for logs ===== */
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

static __cold noinline int deny(const char *why, unsigned int cmd_opt)
{
	const int CMD_BUFLEN = 256;
	char *cmdbuf = kmalloc(CMD_BUFLEN, GFP_ATOMIC);

#if defined(CONFIG_SECURITY_SELINUX)
	bool enforcing = false;
	const char *ctx = NULL;
	(void)current_domain_allowed_fast(&enforcing, &ctx); /* only for printing state */
	if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);
	if (cmd_opt) {
		if (ctx)
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%s\" cmd=0x%x argv=\"%s\"\n",
				why, enforcing ? 1 : 0, ctx, cmd_opt, cmdbuf ? cmdbuf : "?");
		else
			pr_info("baseband_guard: deny %s (enforcing=%d) cmd=0x%x argv=\"%s\"\n",
				why, enforcing ? 1 : 0, cmd_opt, cmdbuf ? cmdbuf : "?");
	} else {
		if (ctx)
			pr_info("baseband_guard: deny %s (enforcing=%d) domain=\"%s\" argv=\"%s\"\n",
				why, enforcing ? 1 : 0, ctx, cmdbuf ? cmdbuf : "?");
		else
			pr_info("baseband_guard: deny %s (enforcing=%d) argv=\"%s\"\n",
				why, enforcing ? 1 : 0, cmdbuf ? cmdbuf : "?");
	}
#else
	if (cmdbuf)
		pr_info("baseband_guard: deny %s argv=\"%s\"\n", why, cmdbuf);
	else
		pr_info("baseband_guard: deny %s\n", why);
#endif
	kfree(cmdbuf);
	return -EPERM;
}

/* ===== readiness gating ===== */
static struct workqueue_struct *bbg_wq;
static struct delayed_work bbg_poll_work;
static bool bbg_ready; /* once true -> enforce */
static unsigned int poll_interval_ms = 500;

static bool is_data_mounted_once(void)
{
	struct path p;
	if (!kern_path("/data", LOOKUP_FOLLOW, &p)) {
		path_put(&p);
		return true;
	}
	return false;
}

static bool is_current_zygote_comm(void)
{
	char comm[TASK_COMM_LEN];
	get_task_comm(comm, current);
	return (!strcmp(comm, "app_process64") || !strcmp(comm, "app_process32"));
}

static void bbg_poll_worker(struct work_struct *ws)
{
	if (bbg_ready) return;

	if (is_data_mounted_once()) {
		bbg_ready = true;
		pr_info("baseband_guard: /data is mounted\n");
		return;
	}

	if (is_current_zygote_comm()) {
		bbg_ready = true;
		pr_info("baseband_guard: zygote detected (pid=%d)\n", current->pid);
		return;
	}

	queue_delayed_work(bbg_wq, &bbg_poll_work, msecs_to_jiffies(poll_interval_ms));
}

/* ===== enforcement hooks ===== */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	if (unlikely(!bbg_ready)) return 0;          /* not yet enforcing at boot */
	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	rdev = inode->i_rdev;

	/* Domain allow：仅在 Enforcing 生效；命中则完全交给 SELinux */
	{
		bool enforcing = selinux_is_enforcing_now();
		if (enforcing) {
			bool dom_ok = current_domain_allowed_fast(NULL, NULL);
			if (dom_ok) return 0;
		}
	}

	/* Partition allow：命中则交给 SELinux */
	if (allow_has(rdev)) return 0;

	/* 首遇 dev_t：若反查到允许分区，缓存并交给 SELinux */
	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	/* 其它情况：拦截并打印详细日志 */
	denied_seen_add(rdev);
	return deny("write to protected partition", 0);
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

	if (unlikely(!bbg_ready)) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(!is_destructive_ioctl(cmd)))
		return 0;

	rdev = inode->i_rdev;

	{
		bool enforcing = selinux_is_enforcing_now();
		if (enforcing) {
			bool dom_ok = current_domain_allowed_fast(NULL, NULL);
			if (dom_ok) return 0;
		}
	}

	if (allow_has(rdev)) return 0;

	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	denied_seen_add(rdev);
	return deny("destructive ioctl on protected partition", cmd);
}

/* 6.6: file_ioctl_compat 存在；旧核可能没有 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

/* ===== LSM registration ===== */
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

	bbg_wq = alloc_ordered_workqueue("bbg_poll_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (bbg_wq) {
		INIT_DELAYED_WORK(&bbg_poll_work, bbg_poll_worker);
		queue_delayed_work(bbg_wq, &bbg_poll_work, msecs_to_jiffies(poll_interval_ms));
	}

	/* compute slot suffix once (best-effort) */
	bbg_slot_suffix = slot_suffix_from_cmdline_once();

	pr_info("baseband_guard (diagnostic log build: every deny prints enforcing/domain/argv; /data&zygote poll)\n");
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

MODULE_DESCRIPTION("Global block with SELinux-enforcing-aware domain allow, dev_t reverse allow; diagnostic logging");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");