// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard_perf: Global partition guard with minimal CPU overhead.
 *
 * - 默认：写块设备 & 破坏性 ioctl → 拒绝（-EPERM）
 * - 例外（本 LSM 不提前放行，交由 SELinux 裁决 = return 0）：
 *     1) 进程 SELinux 域包含子串：update_engine / fastbootd / recovery / rmt_storage
 *     2) 分区在 allowlist（含 a/b/slot 后缀），并带“首写反查 dev_t→缓存”
 *
 * - 性能优化：
 *     * allowed_devs：命中允许分区后缓存 dev_t（O(1)）
 *     * denied_seen ：未命中允许分区的 dev_t 记录一次（O(1)），避免重复反查
 *     * SID 快速缓存：同一进程域复用判断结果
 *
 * - 日志：ratelimited，去掉 disk= 字段；堆缓冲避免大栈帧。
 * - 适配 Linux 6.6 API
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
#include <linux/dcache.h>
#include <linux/hashtable.h>

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ===== 进程白名单（模糊匹配 SELinux 域子串）===== */
static const char * const allowed_domain_substrings[] = {
	"update_engine",
	"fastbootd",
	"recovery",
	"rmt_storage",
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

/*
 * ===== 分区白名单（交给 SELinux；本 LSM 不介入最终许可）=====
 * 为保证系统可用，这里包含 userdata/cache/metadata/misc + 引导类。
 * 如需更严可删，但可能影响可用性。
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

/* ===== by-name → dev_t ===== */
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

/* ===== 允许 dev_t 缓存（首写反查成功后加入）===== */
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

/* ===== dev_t 否定缓存：未命中允许分区，仅记录一次，避免重复反查 ===== */
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

/* ===== 白名单匹配：直接解析（每次）===== */
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

/* ===== 首写反查兜底：当前 dev_t ←→ 允许分区 by-name；命中则缓存 ===== */
static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_allowed_partition_dev_resolve(cur)) { allow_add(cur); return true; }
	return false;
}

/* ===== SELinux 域白名单（子串） + SID 快速缓存 ===== */
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

/* ===== 日志（去掉 disk=；小堆缓冲；ratelimit）===== */

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

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

static void bbg_log_deny_detail(const char *why, struct file *file, unsigned int cmd_opt)
{
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	struct inode *inode = file ? file_inode(file) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf) bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

#if BB_VERBOSE
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	}
#else
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid);
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid);
	}
#endif

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;
	bbg_log_deny_detail(why, file, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	return -EPERM;
}

/* ===== 执法点 ===== */

/* 写：默认拒绝；命中进程/分区白名单（含首写反查缓存）→ 交由 SELinux */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;
	dev_t rdev;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	rdev = inode->i_rdev;

	/* 进程白名单（SELinux 域子串）：交由 SELinux 裁决 */
	if (current_domain_allowed_fast())
		return 0;

	/* 分区白名单：允许 dev_t 命中缓存 → 交由 SELinux 裁决 */
	if (allow_has(rdev))
		return 0;

	/* 对“没见过的 dev_t”且未在否定缓存里，做一次首写反查；命中则缓存并交给 SELinux */
	if (!denied_seen_has(rdev) && reverse_allow_match_and_cache(rdev))
		return 0;

	/* 反查失败 → 记入否定缓存，后续不再反查 */
	denied_seen_add(rdev);

	/* 其余：默认拒绝 */
	return deny("write to protected partition", file, 0);
}

/* 仅拦截破坏性 ioctl；命中“进程/分区白名单” → 交给 SELinux */
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
	pr_info("baseband_guard_perf: init (global block; dev_t allow/deny caches; SID cache; defer to SELinux on allow)\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("Global partition guard with dev_t allow/deny caches and SELinux-deferred allow (no disk field in logs)");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");