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
#include <linux/mount.h>
#include <linux/dcache.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ---------- Allowlist: process (substring match on comm / argv) ---------- */
static const char * const allowed_comm_substrings[] = {
	"update_engine",
	"update_engine_sideload",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"hal_bootctl", "bootctl",
	"fsck", "e2fsck", "f2fs", "resize", "tune2fs",
	"swap", "mkswap", "zram",
	"vendor_qti", "mi_ric",
	"oplus", "oppo",
	"feature", "system_perf_init",
};
static const size_t allowed_comm_substrings_cnt = ARRAY_SIZE(allowed_comm_substrings);

/* ---------- Allowlist: partitions (defer to SELinux if matched) ---------- */
/* Keep userland workable and OEM routines happy */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc","zarm0"
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ---------- Slot suffix (computed once, if available) ---------- */
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

/* ---------- /data or zygote readiness ---------- */
static bool bbg_ready;
static struct delayed_work bbg_poll_work;
static struct workqueue_struct *bbg_wq;
static unsigned int bbg_poll_ms = 1000; /* stop after ready */
module_param(bbg_poll_ms, uint, 0644);
MODULE_PARM_DESC(bbg_poll_ms, "Polling interval (ms) for /data mount or zygote detection until ready");

static __always_inline bool bbg_data_mounted(void)
{
	struct path p;
	if (!kern_path("/data", LOOKUP_FOLLOW, &p)) {
		bool ok = S_ISDIR(d_inode(p.dentry)->i_mode);
		path_put(&p);
		return ok;
	}
	return false;
}

static __always_inline bool bbg_zygote_seen_once(void)
{
	struct task_struct *g, *t;
	bool seen = false;

	rcu_read_lock();
	for_each_process_thread(g, t) {
		if (t->comm[0] == '\0')
			continue;
		if (strnstr(t->comm, "app_process", TASK_COMM_LEN) ||
		    strnstr(t->comm, "zygote", TASK_COMM_LEN)) {
			seen = true;
			break;
		}
	}
	rcu_read_unlock();
	return seen;
}

static void bbg_poll_worker(struct work_struct *ws)
{
	if (bbg_ready) return;

	if (bbg_data_mounted() || bbg_zygote_seen_once()) {
		bbg_ready = true;
#if BB_VERBOSE
		pr_info("baseband_guard: READY (policy enabled)\n");
#endif
		return;
	}
	queue_delayed_work(bbg_wq, &bbg_poll_work, msecs_to_jiffies(bbg_poll_ms));
}

/* ---------- by-name -> dev_t (cross-version, via kern_path) ---------- */
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

/* ---------- allow dev cache ---------- */
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

/* ---------- denied-seen dev cache (avoid repeat reverse lookups) ---------- */
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

/* ---------- is allowed partition? (with slot variants) ---------- */
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

/* ---------- first-write reverse match & cache ---------- */
static __always_inline bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ---------- process allow (substring match on comm and argv) ---------- */
static __always_inline bool current_process_allowed_fast(void)
{
	size_t i;

	/* comm: fast path */
	if (current->comm[0] != '\0') {
		for (i = 0; i < allowed_comm_substrings_cnt; i++) {
			const char *needle = allowed_comm_substrings[i];
			if (needle && *needle &&
			    strnstr(current->comm, needle, TASK_COMM_LEN))
				return true;
		}
	}

	/* argv: slow path, only if needed */
	{
		char buf[192]; /* small and bounded */
		int n = get_cmdline(current, buf, sizeof(buf));
		if (n > 0) {
			int j;
			for (j = 0; j < n - 1; j++)
				if (buf[j] == '\0') buf[j] = ' ';
			buf[min(n, (int)sizeof(buf) - 1)] = '\0';

			for (i = 0; i < allowed_comm_substrings_cnt; i++) {
				const char *needle = allowed_comm_substrings[i];
				if (needle && *needle && strstr(buf, needle))
					return true;
			}
		}
	}
	return false;
}

/* ---------- logging (only pid + argv) ---------- */
static unsigned int quiet_boot_ms = 10000; /* early boot quiet */
module_param(quiet_boot_ms, uint, 0644);
MODULE_PARM_DESC(quiet_boot_ms, "Suppress deny logs during early boot window (ms)");

static unsigned int per_dev_log_limit = 1; /* max logs per dev this boot */
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

static __cold noinline void bbg_log_(unsigned int cmd_opt)
{
	/* Only pid + argv */
	char buf[256];
	int n = get_cmdline(current, buf, sizeof(buf));

	if (n > 0) {
		int i;
		for (i = 0; i < n - 1; i++)
			if (buf[i] == '\0') buf[i] = ' ';
		buf[min(n, (int)sizeof(buf) - 1)] = '\0';
	} else {
		buf[0] = '?'; buf[1] = '\0';
	}

	if (cmd_opt)
		pr_info_ratelimited("baseband_guard:  (pid=%d) argv=\"%s\"\n",
				    current->pid, buf);
	else
		pr_info_ratelimited("baseband_guard: qdykernel deny (pid=%d) argv=\"%s\"\n",
				    current->pid, buf);
}

static __cold noinline int deny(struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;

	/* early boot silent window: enforce without logs */
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

	bbg_log_deny(cmd_opt);
	return -EPERM;
}

/* ---------- ioctl destructive set ---------- */
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

/* ---------- LSM hooks (hot path) ---------- */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	/* 仅就绪后启用策略：就绪前不拦截 */
	if (unlikely(!bbg_ready)) return 0;

	if (likely(!(mask & MAY_WRITE))) return 0;
	if (unlikely(!file)) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	rdev = inode->i_rdev;

	/* 允许的进程：放行，交给 SELinux 决定 */
	if (unlikely(current_process_allowed_fast()))
		return 0;

	/* 分区白名单：放行，交给 SELinux 决定 */
	if (likely(allow_has(rdev)))
		return 0;

	/* 首次遇到：做一次反查命中即缓存放行 */
	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	/* miss：记忆并拒绝 */
	denied_seen_add(rdev);
	return deny(file, 0);
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

	if (unlikely(current_process_allowed_fast()))
		return 0;

	if (likely(allow_has(rdev)))
		return 0;

	if (unlikely(!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev)))
		return 0;

	denied_seen_add(rdev);
	return deny(file, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#define BB_HAVE_IOCTL_COMPAT 1
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,   bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,        bb_file_ioctl),
#ifdef BB_HAVE_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
};

/* ---------- init / exit ---------- */
static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");

	/* compute slot suffix (if present) */
	bbg_slot_suffix = slot_suffix_from_cmdline_once();

	/* readiness poll worker (stops once ready) */
	bbg_wq = alloc_ordered_workqueue("bbg_wq", WQ_UNBOUND | WQ_FREEZABLE);
	if (bbg_wq) {
		INIT_DELAYED_WORK(&bbg_poll_work, bbg_poll_worker);
		queue_delayed_work(bbg_wq, &bbg_poll_work, msecs_to_jiffies(bbg_poll_ms));
	}

	bbg_boot_jiffies = jiffies;

	pr_info("baseband_guard power by qdykernel\n");
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

MODULE_DESCRIPTION("Baseband/boot partitions guard with readiness gating and fast-path optimizations");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");
