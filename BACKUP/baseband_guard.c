// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_perf: Global partition guard with minimal CPU overhead.
 *
 * 策略：
 * - 默认对所有块设备写与破坏性 ioctl 拦截（-EPERM）。
 * - 命中“进程域子串白名单”或“分区白名单（含 a/b/slot 后缀）”时，
 *   本 LSM 不提前放行，return 0 交由 SELinux 裁决（避免 neverallow 争议）。
 *
 * 性能优化：
 * - allowed_devs：命中允许分区后缓存 dev_t，后续 O(1)。
 * - denied_seen ：未命中允许分区的 dev_t 做一次反查后加入，后续不再反查。
 * - SID 快速缓存：同一进程域复用判断结果，减少 secctx 字符串处理。
 *
 * 日志：
 * - 仅单行 ratelimited 拒绝日志（只打印 argv）。
 * - 启动静默窗口（前 quiet_boot_ms 毫秒不打日志，仅拦截）。
 * - 每个 dev_t 最多打印 per_dev_log_limit 次拒绝日志。
 *
 * 兼容：Linux 6.6
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

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ===== 进程域白名单（模糊匹配 SELinux 域子串） ===== */
static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
	"oplus",
	"oppo",
	"feature",
	"swap","
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

/*
 * ===== 分区白名单（命中则“交给 SELinux 决定”，本 LSM 不提前放行） =====
 * 注意：包含 userdata/cache/metadata/misc 以保证系统可用；如需更严可调整。
 */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== slot 后缀解析 ===== */
extern char *saved_command_line; /* from init/main.c */
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

/* ===== by-name → dev_t 解析 ===== */
static bool resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	dev_t dev;
	int ret;

	if (!name || !out) return false;

	path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

	ret = lookup_bdev(path, &dev);
	kfree(path);
	if (ret) return false;

	*out = dev;
	return true;
}

/* ===== 允许 dev_t 缓存（命中 allowlist 后加入） ===== */
struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 7); /* 128 桶 */

static bool allow_has(dev_t dev)
{
	struct allow_node *p;
	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
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

/* ===== dev_t 否定缓存：未命中 allowlist 的只记一次，后续不再反查 ===== */
struct seen_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(denied_seen, 7); /* 128 桶 */

static bool denied_seen_has(dev_t dev)
{
	struct seen_node *p;
	hash_for_each_possible(denied_seen, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void denied_seen_add(dev_t dev)
{
	struct seen_node *n;
	if (!dev || denied_seen_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(denied_seen, &n->h, (u64)dev);
}

/* ===== allowlist 解析：当前 dev_t 是否属于“允许分区” ===== */
static bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i;
	dev_t dev;
	const char *suf = slot_suffix_from_cmdline();

	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];
		bool ok = false;

		if (resolve_byname_dev(n, &dev) && dev == cur) return true;

		if (!ok && suf) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", n, suf);
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

/* ===== 首写反查兜底：命中允许分区则加入 allowed_devs ===== */
static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== SELinux 域白名单（子串匹配） + SID 快速缓存 ===== */
#ifdef CONFIG_SECURITY_SELINUX
static u32 sid_cache_last;
static bool sid_cache_last_ok;
#endif

static bool current_domain_allowed_fast(void)
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
	security_release_secctx(ctx, len);

	sid_cache_last = sid;
	sid_cache_last_ok = ok;
	return ok;
#else
	return false;
#endif
}

/* ===== Logging throttles & helpers ===== */
static unsigned int quiet_boot_ms = 10000; /* 引导早期静默，仅拦截 */
module_param(quiet_boot_ms, uint, 0644);
MODULE_PARM_DESC(quiet_boot_ms, "Suppress deny logs during early boot window (ms)");

static unsigned int per_dev_log_limit = 1; /* 每个 dev 最多打印 N 条拒绝日志 */
module_param(per_dev_log_limit, uint, 0644);
MODULE_PARM_DESC(per_dev_log_limit, "Max deny logs per block dev_t this boot");

static unsigned long bbg_boot_jiffies; /* 记录 init 时刻 */

/* 已记录过的 dev 计数表 */
struct log_node { dev_t dev; u32 cnt; struct hlist_node h; };
DEFINE_HASHTABLE(denied_logged, 7);

static bool bbg_should_log(dev_t dev)
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
	/* 第一次：插入并计数为 1 */
	p = kmalloc(sizeof(*p), GFP_ATOMIC);
	if (!p) return false;
	p->dev = dev;
	p->cnt = 1;
	hash_add(denied_logged, &p->h, (u64)dev);
	return true;
}

/* 取当前进程命令行（\0 → 空格） */
static int bbg_get_cmdline(char *buf, int buflen)
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

/* === 仅输出命令行（argv），不打印 path / scontext === */
static void bbg_log_deny_detail(const char *why, struct file *file, unsigned int cmd_opt)
{
	const int CMD_BUFLEN  = 256;
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x argv=\"%s\"\n",
			why, cmd_opt, cmdbuf ? cmdbuf : "?"
		);
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s argv=\"%s\"\n",
			why, cmdbuf ? cmdbuf : "?"
		);
	}

	kfree(cmdbuf);
}

static int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;

	/* 引导静默窗口：仍然拦截，但不打日志 */
	if (quiet_boot_ms &&
	    time_before(jiffies, bbg_boot_jiffies + msecs_to_jiffies(quiet_boot_ms)))
		return -EPERM;

	/* 每个 dev 只打前 per_dev_log_limit 条日志，避免刷屏 */
	if (file) {
		struct inode *inode = file_inode(file);
		if (inode && S_ISBLK(inode->i_mode)) {
			dev_t dev = inode->i_rdev;
			if (!bbg_should_log(dev))
				return -EPERM;
		}
	}

	/* 单行简洁日志：只含 argv */
	bbg_log_deny_detail(why, file, cmd_opt);
	return -EPERM;
}

/* ===== 执法点 ===== */

/* 写：默认拒绝；命中进程/分区白名单（含首写反查缓存）→ 交由 SELinux 裁决 */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	rdev = inode->i_rdev;

	/* 进程域白名单（子串）：交由 SELinux 裁决 */
	if (current_domain_allowed_fast())
		return 0;

	/* 分区白名单：命中缓存 → 交由 SELinux 裁决 */
	if (allow_has(rdev))
		return 0;

	/* 未见过的 dev_t：做一次首写反查；命中则缓存并交由 SELinux */
	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	/* 反查失败：记入否定缓存，后续不再反查；本 LSM 拒绝 */
	denied_seen_add(rdev);
	return deny("write to protected partition", file, 0);
}

/* 仅拦截破坏性 ioctl；命中进程/分区白名单 → 交由 SELinux 裁决 */
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

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;
	dev_t rdev;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

/* ===== LSM 注册 ===== */

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
	bbg_boot_jiffies = jiffies;  /* 记录 init 时间点 */
	pr_info("baseband_guard_perf: init (power by TG@qdykernel; quiet=%ums per_dev=%u)\n",
		quiet_boot_ms, per_dev_log_limit);
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("protect ALL form TG@qdykernel");
MODULE_AUTHOR("秋刀鱼&https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");
