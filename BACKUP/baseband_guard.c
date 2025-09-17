// SPDX-License-Identifier: GPL-2.0
// Baseband/Bootloader partition write guard (LSM)
// Rev: enforce-after-armed + performance-tuned
// Behavior summary:
//  - Not armed until BOTH: real /data mounted OR zygote about to exec, AND selinux_enforcing==1
//  - After armed: default deny writes & destructive ioctls to any block device
//  - Defer to SELinux if (selinux_enforcing && proc domain fuzzy-match) OR (partition allowlist match)
//  - Log only on deny (argv, per dev_t once)
//  - Small caches for allowed/denied devices; reverse by-name->dev_t at arm time and on first-seen
//  - Cross-version hooks: sb_mount signature (<=6.2 vs 6.3+), file_ioctl(_compat) (6.6+)
//  - Hot paths use likely()/unlikely(), __always_inline, and noinline for cold paths

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/binfmts.h>

// ---- SELinux weak symbols (safe fallback when SELinux is off) ----
#ifdef CONFIG_SECURITY_SELINUX
extern int selinux_enabled __attribute__((weak));
extern int selinux_enforcing __attribute__((weak));
#else
static const int selinux_enabled = 0;
static const int selinux_enforcing = 0;
#endif

#define BG_TAG           "baseband_guard"
#define BG_LOG(fmt, ...) pr_info(BG_TAG ": " fmt "\n", ##__VA_ARGS__)
#define BG_WARN(fmt, ...) pr_warn(BG_TAG ": " fmt "\n", ##__VA_ARGS__)
#define BG_ERR(fmt, ...)  pr_err(BG_TAG ": " fmt "\n", ##__VA_ARGS__)

#ifndef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BG_VERBOSE 0
#else
#define BG_VERBOSE 1
#endif

// Partition allowlist (by-name, defer-to-SELinux)
static const char * const bg_part_allowlist[] = {
    "boot", "init_boot", "dtbo", "vendor_boot",
    "userdata", "cache", "metadata", "misc",
};

// Domain fuzzy allowlist (substring), only when SELinux=Enforcing
static const char * const bg_domain_allow_substr[] = {
    "update_engine",
    "fastbootd",
    "recovery",
    "rmt_storage",
    // vendor variations
    "oplus", "oppo", "feature", "swap", "system_perf_init",
    "hal_bootctl_default", "fsck", "vendor_qti", "mi_ric",
};

// Device-name exact allowlist (non-physical block devices to defer to SELinux)
static const char * const bg_device_allow_exact[] = {
    "zram0",
};

#ifndef BLKZEROOUT
#define BLKZEROOUT _IO(0x12,127)
#endif
#ifndef BLKSECDISCARD
#define BLKSECDISCARD _IO(0x12,125)
#endif
#ifndef BLKDISCARD
#define BLKDISCARD _IO(0x12,119)
#endif
#ifndef BLKTRIM
#define BLKTRIM _IO(0x12, 96)
#endif
#ifndef BLKSETRO
#define BLKSETRO _IO(0x12,93)
#endif
#ifndef BLKPG
#define BLKPG _IO(0x12,105)
#endif

static __always_inline bool bg_is_destructive_ioctl(unsigned int cmd)
{
    switch (cmd) {
    case BLKDISCARD:
    case BLKSECDISCARD:
    case BLKZEROOUT:
    case BLKTRIM:
    case BLKSETRO:
    case BLKPG:
        return true;
    default:
        return false;
    }
}

// ---- State & caches ---------------------------------------------------------
static DEFINE_MUTEX(bg_lock);
static bool bg_armed;
static bool bg_data_mounted;

DEFINE_HASHTABLE(bg_allowed_devs, 8);  // ~256 buckets
DEFINE_HASHTABLE(bg_denied_devs, 8);
DEFINE_HASHTABLE(bg_logged_devs, 8);

struct bg_dev_entry { dev_t dev; struct hlist_node node; };

static __always_inline bool bg_cache_has(struct hlist_head *tbl, dev_t d)
{
    struct bg_dev_entry *e;
    hash_for_each_possible(*tbl, e, node, (u64)d)
        if (likely(e->dev == d)) return true;
    return false;
}

static __always_inline void bg_cache_put(struct hlist_head *tbl, dev_t d)
{
    struct bg_dev_entry *e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (unlikely(!e)) return;
    e->dev = d;
    hash_add(*tbl, &e->node, (u64)d);
}

// ---- Utilities --------------------------------------------------------------
static __always_inline bool bg_selinux_enforcing_now(void)
{
    return likely(selinux_enabled == 1) && likely(selinux_enforcing == 1);
}

static __always_inline const char *bg_current_basename(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

// log only once per dev_t
static __always_inline void bg_log_deny_once(dev_t dev, const char *argv0)
{
    if (unlikely(!bg_cache_has(&bg_logged_devs, dev))) {
        BG_WARN("deny write to protected partition argv=\"%s\"", argv0);
        bg_cache_put(&bg_logged_devs, dev);
    }
}

// Resolve /dev/block/by-name/<part> to dev_t
static noinline dev_t bg_resolve_by_name_locked(const char *name)
{
    char path[128];
    struct path p;
    struct inode *inode;
    dev_t dev = 0;

    snprintf(path, sizeof(path), "/dev/block/by-name/%s", name);
    if (kern_path(path, LOOKUP_FOLLOW, &p))
        return 0;
    inode = d_backing_inode(p.dentry);
    if (inode && S_ISBLK(inode->i_mode))
        dev = inode->i_rdev;
    path_put(&p);
    return dev;
}

static noinline bool bg_is_exact_data_path(const struct path *path)
{
    char *buf = NULL, *abspath = NULL;
    bool ok = false;

    buf = (char *)__get_free_page(GFP_ATOMIC);
    if (!buf) return false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    abspath = d_path(path, buf, PAGE_SIZE);
#else
    abspath = d_path((struct path *)path, buf, PAGE_SIZE);
#endif
    if (!IS_ERR(abspath))
        ok = (strcmp(abspath, "/data") == 0);
    free_page((unsigned long)buf);
    return ok;
}

static __always_inline bool bg_match_domain_substr(const char *dom)
{
    size_t i;
    if (unlikely(!dom)) return false;
    for (i = 0; i < ARRAY_SIZE(bg_domain_allow_substr); i++)
        if (strnstr(dom, bg_domain_allow_substr[i], strlen(dom)))
            return true;
    return false;
}

// Best-effort to get SELinux domain label of current task (no set_fs on 5.10+)
static noinline const char *bg_current_domain(char *buf, size_t buflen)
{
    struct file *f;
    int len;
    pid_t pid = task_pid_nr(current);
    char path[64];
    loff_t pos = 0;

    snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) return NULL;
    len = kernel_read(f, buf, buflen - 1, &pos);
    filp_close(f, NULL);
    if (len <= 0) return NULL;
    buf[len] = '\0';
    if (buf[len-1] == '\n') buf[len-1] = '\0';
    return buf;
}

static __always_inline bool bg_device_basename_allowed_exact(const char *bname)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(bg_device_allow_exact); i++)
        if (likely(!strcmp(bname, bg_device_allow_exact[i])))
            return true;
    return false;
}

// ---- Policy decisions -------------------------------------------------------
static noinline bool bg_should_defer_to_selinux(dev_t dev, struct file *file)
{
    size_t i; dev_t mapped;

    // 1) Partition allowlist (by-name -> dev_t)
    for (i = 0; i < ARRAY_SIZE(bg_part_allowlist); i++) {
        mapped = bg_resolve_by_name_locked(bg_part_allowlist[i]);
        if (mapped && mapped == dev)
            return true; // Defer
    }

    // 2) Device exact allowlist (e.g., zram0)
    if (S_ISBLK(file_inode(file)->i_mode)) {
        const char *bname = bg_current_basename(file->f_path.dentry->d_name.name);
        if (bg_device_basename_allowed_exact(bname))
            return true;
    }

    // 3) Domain fuzzy allowlist (only when SELinux is Enforcing)
    if (bg_selinux_enforcing_now()) {
        char dom[128];
        const char *d = bg_current_domain(dom, sizeof(dom));
        if (d && bg_match_domain_substr(d))
            return true;
    }
    return false;
}

static __always_inline bool bg_is_write(const struct file *file, int mask)
{
#ifdef FMODE_WRITE
    if (likely((mask & MAY_WRITE) || (file->f_mode & FMODE_WRITE)))
        return true;
#else
    if (likely(mask & MAY_WRITE))
        return true;
#endif
    return false;
}

static __always_inline const char *bg_comm(void)
{
    return current->comm; // short argv0-equivalent, stable
}

static int bg_guard(dev_t dev, struct file *file, int mask, bool is_ioctl, unsigned int cmd)
{
    // Not armed -> no-op (in early boot)
    if (unlikely(!READ_ONCE(bg_armed)))
        return 0;

    // Quick allow/deny via caches
    if (likely(bg_cache_has(&bg_allowed_devs, dev)))
        return 0; // Defer to SELinux implicitly
    if (unlikely(bg_cache_has(&bg_denied_devs, dev))) {
        bg_log_deny_once(dev, bg_comm());
        return -EPERM;
    }

    // Writes or destructive ioctls only
    if (likely(!is_ioctl)) {
        if (likely(!bg_is_write(file, mask)))
            return 0;
    } else {
        if (likely(!bg_is_destructive_ioctl(cmd)))
            return 0;
    }

    // Decide: defer-to-SELinux or hard-deny
    mutex_lock(&bg_lock);
    {
        bool defer = bg_should_defer_to_selinux(dev, file);
        if (defer) {
            bg_cache_put(&bg_allowed_devs, dev);
            mutex_unlock(&bg_lock);
            return 0;
        }
        bg_cache_put(&bg_denied_devs, dev);
    }
    mutex_unlock(&bg_lock);

    // Cold path: actual deny + rate-limited log
    bg_log_deny_once(dev, bg_comm());
    return -EPERM;
}

// ---- Hooks ------------------------------------------------------------------
static int bg_file_permission(struct file *file, int mask)
{
    struct inode *inode = file_inode(file);
    if (unlikely(!S_ISBLK(inode->i_mode))) return 0;
    return bg_guard(inode->i_rdev, file, mask, false, 0);
}

static long bg_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct inode *inode = file_inode(file);
    if (unlikely(!S_ISBLK(inode->i_mode))) return 0;
    return bg_guard(inode->i_rdev, file, 0, true, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static long bg_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
    return bg_file_ioctl(file, cmd, arg);
}
#endif

// Arm when BOTH: (exact /data mounted OR zygote bprm) AND SELinux enforcing
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
static int bg_sb_mount(const char *dev_name, const struct path *path, const char *type,
                       unsigned long flags, void *data)
#else
static int bg_sb_mount(const char *dev_name, struct path *path, const char *type,
                       unsigned long flags, void *data)
#endif
{
    if (unlikely(!READ_ONCE(bg_armed))) {
        bool is_data = bg_is_exact_data_path(path);
        if (is_data) {
            WRITE_ONCE(bg_data_mounted, true);
            if (bg_selinux_enforcing_now()) {
                WRITE_ONCE(bg_armed, true);
#if BG_VERBOSE
                BG_LOG("armed=1 selinux=1 reason=data_mount");
#endif
            } else {
#if BG_VERBOSE
                BG_LOG("data mounted but selinux!=enforcing; keep unarmed");
#endif
            }
        }
    }
    return 0;
}

static int bg_bprm_check_security(struct linux_binprm *bprm)
{
    const char *bn = bprm->filename ? bg_current_basename(bprm->filename) : NULL;
    if (unlikely(!READ_ONCE(bg_armed) && bn)) {
        if (unlikely(!strcmp(bn, "app_process32") || !strcmp(bn, "app_process64"))) {
            if (bg_selinux_enforcing_now()) {
                WRITE_ONCE(bg_armed, true);
#if BG_VERBOSE
                BG_LOG("armed=1 selinux=1 reason=zygote");
#endif
            } else {
#if BG_VERBOSE
                BG_LOG("zygote seen but selinux!=enforcing; keep unarmed");
#endif
            }
        }
    }
    return 0;
}

static struct security_hook_list bg_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_permission, bg_file_permission),
    LSM_HOOK_INIT(file_ioctl,      bg_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
    LSM_HOOK_INIT(file_ioctl_compat, bg_file_ioctl_compat),
#endif
    LSM_HOOK_INIT(sb_mount,        bg_sb_mount),
    LSM_HOOK_INIT(bprm_check_security, bg_bprm_check_security),
};

// ---- Init -------------------------------------------------------------------
static int __init baseband_guard_init(void)
{
    hash_init(bg_allowed_devs);
    hash_init(bg_denied_devs);
    hash_init(bg_logged_devs);

    BG_LOG("power by https://t.me/qdykernel");
    security_add_hooks(bg_hooks, ARRAY_SIZE(bg_hooks), BG_TAG);
    return 0;
}

DEFINE_LSM(baseband_guard) = {
    .name = BG_TAG,
    .init = baseband_guard_init,
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Baseband/Bootloader partition write guard (LSM)");
MODULE_AUTHOR("秋刀鱼 & contributors");