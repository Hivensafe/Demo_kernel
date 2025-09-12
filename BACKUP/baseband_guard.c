// SPDX-License-Identifier: GPL-2.0

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
#include <linux/limits.h>

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
	"oplus",
	"oppo",
	"feature",
	"swap",
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

/*
 * ===== 分区白名单（交给 SELinux；本 LSM 不介入）=====
 * 为保证系统可用，这里包含 userdata/cache/metadata 以及 boot/init_boot/dtbo/vendor_boot。
 * 如需更严可删，但会引发可用性问题。
 */
static const char * const allowlist_names[] = {
	"boot", "init_boot", "dtbo", "vendor_boot",
	"userdata", "cache", "metadata", "misc",
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

/* ===== slot 后缀 ===== */
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

/* 分区白名单匹配：尝试 name、name+slot_suffix、name_a/name_b */
static bool is_allowed_partition_dev(dev_t cur)
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

/* ===== SELinux 域白名单（子串）===== */
static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;  /* 非 const，便于释放 */
	u32 len = 0;
	bool ok = false;
	size_t i;

	security_cred_getsecid(current_cred(), &sid);
	if (!sid) return false;
	if (security_secid_to_secctx(sid, &ctx, &len)) return false;
	if (!ctx || !len) goto out;

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
	return false;
#endif
}

/* ===== 日志辅助（堆分配，避免大栈帧）===== */

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

/* get_cmdline + 将 NUL 替换为空格，便于阅读 */
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

/* 小心：仅用于日志，失败就用占位符；全部使用 GFP_ATOMIC 并检查空指针 */
static void bbg_log_deny_detail(const char *why, struct file *file, unsigned int cmd_opt)
{
	/* 适度长度，避免刷屏；无需 PATH_MAX */
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	struct inode *inode = file ? file_inode(file) : NULL;
	struct block_device *bdev = inode && S_ISBLK(inode->i_mode) ? I_BDEV(inode) : NULL;
	const char *dname = (bdev && bdev->bd_disk) ? bdev->bd_disk->disk_name : "?";
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

#if BB_VERBOSE
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u disk=%s path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev), dname, path ? path : "?",
			current->pid, current->comm, cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u disk=%s path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev), dname, path ? path : "?",
			current->pid, current->comm, cmdbuf ? cmdbuf : "?");
	}
#else
	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u disk=%s path=%s pid=%d\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev), dname, path ? path : "?", current->pid);
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u disk=%s path=%s pid=%d\n",
			why, MAJOR(dev), MINOR(dev), dname, path ? path : "?", current->pid);
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

/* 写权限：默认拒绝；命中“进程白名单”或“分区白名单” → 交给 SELinux */
static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	/* 进程白名单（模糊域）→ 交给 SELinux 决策 */
	if (current_domain_allowed())
		return 0;

	/* 分区白名单（by-name 映射 dev_t）→ 交给 SELinux 决策 */
	if (is_allowed_partition_dev(inode->i_rdev))
		return 0;

	/* 其余分区 → 一律拒绝 */
	return deny("write to protected partition", file, 0);
}

/* 仅拦截破坏性 ioctl；命中“进程白名单”或“分区白名单” → 交给 SELinux */
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

	if (!file) return 0;
	inode = file_inode(file);
	if (!S_ISBLK(inode->i_mode)) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	/* 进程白名单：交给 SELinux */
	if (current_domain_allowed())
		return 0;

	/* 分区白名单：交给 SELinux */
	if (is_allowed_partition_dev(inode->i_rdev))
		return 0;

	/* 其他任意分区：拒绝 */
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
	pr_info("baseband_guard_all: init (global block; proc/part allow → SELinux)\n");
	return 0;
}

DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
};

MODULE_DESCRIPTION("Global partition guard with SELinux-deferred allow (heap-logged to keep tiny stack)");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");