// SPDX-License-Identifier: GPL-2.0-only
/*
 * Baseband/Bootloader partition write guard LSM
 * 
 * Only arm after:
 *   - /data is mounted AND SELinux is Enforcing, OR
 *   - Zygote starts AND SELinux is Enforcing
 *
 * Before armed: no interception, no overhead
 * After armed: block all partition writes by default; defer to SELinux for allowlisted processes/partitions
 */

#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/mount.h>
#include <linux/binfmts.h>
#include <linux/hashtable.h>
#include <linux/dcache.h>
#include <linux/atomic.h>
#include <linux/delay.h>

// 条件性包含 genhd.h（如果可用）
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include <linux/genhd.h>
#endif

// 配置选项
#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define bbguard_verbose(...) pr_info("baseband_guard: " __VA_ARGS__)
#else
#define bbguard_verbose(...) do {} while (0)
#endif

// 弱引用 SELinux 符号
#ifdef CONFIG_SECURITY_SELINUX
extern bool selinux_enabled __weak;
extern bool selinux_enforcing __weak;
#else
static bool selinux_enabled = false;
static bool selinux_enforcing = false;
#endif

// 全局状态
static atomic_t armed = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(arm_lock);

// 白名单进程域（子串匹配）
static const char *domain_allowlist[] = {
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
    NULL
};

// 白名单分区（by-name）
static const char *partition_allowlist[] = {
    "boot",
    "init_boot",
    "dtbo",
    "vendor_boot",
    "userdata",
    "cache",
    "metadata",
    "misc",
    NULL
};

// 设备缓存
struct dev_cache {
    dev_t dev;
    bool allowed;
    bool logged;
    struct hlist_node node;
};

#define CACHE_SIZE 32
static DEFINE_HAShtABLE(allowed_devs, ilog2(CACHE_SIZE));
static DEFINE_HASHTABLE(denied_seen, ilog2(CACHE_SIZE));
static DEFINE_HASHTABLE(denied_logged, ilog2(CACHE_SIZE));
static DEFINE_SPINLOCK(cache_lock);

// 命令行参数解析
static char *slot_suffix;

// 从 cmdline 解析 slot_suffix
static int __init parse_slot_suffix(char *str)
{
    slot_suffix = kstrdup(str, GFP_KERNEL);
    return 0;
}
early_param("androidboot.slot_suffix", parse_slot_suffix);

// 检查 SELinux 是否处于 Enforcing 模式
static bool is_selinux_enforcing(void)
{
#ifdef CONFIG_SECURITY_SELINUX
    if (&selinux_enabled && !READ_ONCE(selinux_enabled))
        return false;
    if (&selinux_enforcing)
        return READ_ONCE(selinux_enforcing) != 0;
#endif
    return false;
}

// 检查进程域是否在白名单中
static bool is_domain_allowed(const char *domain)
{
    int i;
    
    if (!is_selinux_enforcing()) {
        bbguard_verbose("SELinux not enforcing, domain check skipped\n");
        return false;
    }
    
    if (!domain) {
        bbguard_verbose("No domain provided, domain check failed\n");
        return false;
    }
    
    for (i = 0; domain_allowlist[i]; i++) {
        if (strstr(domain, domain_allowlist[i])) {
            bbguard_verbose("Domain %s allowed by pattern %s\n", domain, domain_allowlist[i]);
            return true;
        }
    }
    
    bbguard_verbose("Domain %s not in allowlist\n", domain);
    return false;
}

// 检查分区名是否在白名单中
static bool is_partition_allowed(const char *name)
{
    int i;
    char devname[64];
    
    if (!name)
        return false;
    
    // 检查基本分区名
    for (i = 0; partition_allowlist[i]; i++) {
        if (strcmp(name, partition_allowlist[i]) == 0)
            return true;
    }
    
    // 检查带 slot 后缀的分区名
    if (slot_suffix) {
        for (i = 0; partition_allowlist[i]; i++) {
            snprintf(devname, sizeof(devname), "%s%s", 
                     partition_allowlist[i], slot_suffix);
            if (strcmp(name, devname) == 0)
                return true;
        }
    }
    
    // 检查带 _a/_b 后缀的分区名
    for (i = 0; partition_allowlist[i]; i++) {
        snprintf(devname, sizeof(devname), "%s_a", partition_allowlist[i]);
        if (strcmp(name, devname) == 0)
            return true;
            
        snprintf(devname, sizeof(devname), "%s_b", partition_allowlist[i]);
        if (strcmp(name, devname) == 0)
            return true;
    }
    
    return false;
}

// 通过设备路径查找设备名
static char *get_devname(dev_t dev)
{
    struct path path;
    char *devpath = NULL;
    char *name = NULL;
    int ret;
    
    devpath = kasprintf(GFP_KERNEL, "/dev/block/%u:%u", 
               MAJOR(dev), MINOR(dev));
    if (!devpath)
        return NULL;
    
    ret = kern_path(devpath, LOOKUP_FOLLOW, &path);
    if (ret)
        goto out;
    
    if (S_ISBLK(d_backing_inode(path.dentry)->i_mode)) {
        struct block_device *bdev = I_BDEV(d_backing_inode(path.dentry));
        if (bdev && bdev->bd_disk) {
            name = kstrdup(bdev->bd_disk->disk_name, GFP_KERNEL);
        }
    }
    
    path_put(&path);
out:
    kfree(devpath);
    return name;
}

// 检查设备是否在白名单中
static bool is_dev_allowed(dev_t dev)
{
    struct dev_cache *cache;
    char *devname;
    bool allowed = false;
    unsigned long flags;
    
    // 首先检查缓存
    spin_lock_irqsave(&cache_lock, flags);
    hash_for_each_possible(allowed_devs, cache, node, dev) {
        if (cache->dev == dev) {
            allowed = cache->allowed;
            spin_unlock_irqrestore(&cache_lock, flags);
            return allowed;
        }
    }
    spin_unlock_irqrestore(&cache_lock, flags);
    
    // 未缓存，解析设备名
    devname = get_devname(dev);
    if (!devname)
        return false;
    
    allowed = is_partition_allowed(devname);
    kfree(devname);
    
    // 缓存结果
    cache = kmalloc(sizeof(*cache), GFP_KERNEL);
    if (cache) {
        cache->dev = dev;
        cache->allowed = allowed;
        cache->logged = false;
        
        spin_lock_irqsave(&cache_lock, flags);
        hash_add(allowed_devs, &cache->node, dev);
        spin_unlock_irqrestore(&cache_lock, flags);
    }
    
    return allowed;
}

// 检查是否已经记录过拒绝
static bool is_dev_denied_logged(dev_t dev)
{
    struct dev_cache *cache;
    unsigned long flags;
    bool logged = false;
    
    spin_lock_irqsave(&cache_lock, flags);
    hash_for_each_possible(denied_seen, cache, node, dev) {
        if (cache->dev == dev) {
            logged = cache->logged;
            break;
        }
    }
    spin_unlock_irqrestore(&cache_lock, flags);
    
    return logged;
}

// 记录拒绝的设备
static void mark_dev_denied_logged(dev_t dev)
{
    struct dev_cache *cache;
    unsigned long flags;
    
    cache = kmalloc(sizeof(*cache), GFP_KERNEL);
    if (!cache)
        return;
    
    cache->dev = dev;
    cache->logged = true;
    
    spin_lock_irqsave(&cache_lock, flags);
        hash_add(denied_seen, &cache->node, dev);
    spin_unlock_irqrestore(&cache_lock, flags);
}

// 检查是否应该记录日志
static bool should_log_denial(dev_t dev)
{
    struct dev_cache *cache;
    unsigned long flags;
    bool should_log = false;
    
    spin_lock_irqsave(&cache_lock, flags);
    hash_for_each_possible(denied_logged, cache, node, dev) {
        if (cache->dev == dev) {
            if (!cache->logged) {
                cache->logged = true;
                should_log = true;
            }
            spin_unlock_irqrestore(&cache_lock, flags);
            return should_log;
        }
    }
    
    // 未找到，创建新条目
    cache = kmalloc(sizeof(*cache), GFP_ATOMIC);
    if (cache) {
        cache->dev = dev;
        cache->logged = true;
        cache->allowed = false; // 未使用
        hash_add(denied_logged, &cache->node, dev);
        should_log = true;
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
    return should_log;
}

// 获取当前进程的 SELinux 上下文
static const char *get_current_security_context(void)
{
#ifdef CONFIG_SECURITY_SELINUX
    u32 sid;
    const char *context = NULL;
    
    if (!is_selinux_enforcing())
        return NULL;
    
    if (security_cred_getsecid(current_cred(), &sid) != 0)
        return NULL;
    
    if (security_secid_to_secctx(sid, &context, NULL) != 0)
        return NULL;
    
    return context;
#else
    return NULL;
#endif
}

// 检查是否应该激活保护
static void check_arming_conditions(void)
{
    unsigned long flags;
    bool should_arm = false;
    
    // 如果已经激活，直接返回
    if (atomic_read(&armed))
        return;
    
    // 检查 SELinux 是否处于 Enforcing 模式
    if (!is_selinux_enforcing()) {
        bbguard_verbose("SELinux not enforcing, skipping arm\n");
        return;
    }
    
    spin_lock_irqsave(&arm_lock, flags);
    if (!atomic_read(&armed)) {
        atomic_set(&armed, 1);
        should_arm = true;
    }
    spin_unlock_irqrestore(&arm_lock, flags);
    
    if (should_arm) {
        bbguard_verbose("protection armed\n");
    }
}

// 文件权限检查钩子
static int bbguard_file_permission(struct file *file, int mask)
{
    struct inode *inode;
    dev_t dev;
    const char *context;
    
    if (!atomic_read(&armed)) {
        bbguard_verbose("not armed, skipping permission check\n");
        return 0;
    }
    
    if (!(mask & MAY_WRITE))
        return 0;
    
    inode = file_inode(file);
    if (!S_ISBLK(inode->i_mode))
        return 0;
    
    dev = inode->i_rdev;
    
    // 检查设备是否在白名单中
    if (is_dev_allowed(dev)) {
        bbguard_verbose("device %u:%u in allowlist, deferring to SELinux\n", 
               MAJOR(dev), MINOR(dev));
        return 0;
    }
    
    // 检查进程域是否在白名单中
    context = get_current_security_context();
    if (context) {
        if (is_domain_allowed(context)) {
            bbguard_verbose("domain %s in allowlist, deferring to SELinux\n", context);
            security_release_secctx(context, strlen(context));
            return 0;
        }
        security_release_secctx(context, strlen(context));
    } else {
        bbguard_verbose("no security context available\n");
    }
    
    // 记录拒绝日志（限流）
    if (should_log_denial(dev)) {
        pr_warn_ratelimited("baseband_guard: denied write to block device %u:%u, process=%s\n",
                   MAJOR(dev), MINOR(dev), current->comm);
    }
    
    return -EPERM;
}

// ioctl 检查钩子
static int bbguard_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct inode *inode;
    dev_t dev;
    const char *context;
    
    if (!atomic_read(&armed))
        return 0;
    
    inode = file_inode(file);
    if (!S_ISBLK(inode->i_mode))
        return 0;
    
    dev = inode->i_rdev;
    
    // 只拦截破坏性 ioctl
    switch (cmd) {
    case BLKFLSBUF:
    case BLKDISCARD:
    case BLKSECDISCARD:
    case BLKZEROOUT:
    case BLKERASE:
#ifdef BLKPG
    case BLKPG:
#endif
#ifdef BLKTRACESETUP
    case BLKTRACESETUP:
#endif
#ifdef BLKTRACESTART
    case BLKTRACESTART:
#endif
#ifdef BLKTRACESTOP
    case BLKTRACESTOP:
#endif
#ifdef BLKTRACETEARDOWN
    case BLKTRACETEARDOWN:
#endif
#ifdef BLKIOMIN
    case BLKIOMIN:
#endif
#ifdef BLKIOOPT
    case BLKIOOPT:
#endif
#ifdef BLKALIGNOFF
    case BLKALIGNOFF:
#endif
#ifdef BLKPBSZGET
    case BLKPBSZGET:
#endif
#ifdef BLKDISCARDZEROES
    case BLKDISCARDZEROES:
#endif
#ifdef BLKSETRO
    case BLKSETRO:
#endif
        break;
    default:
        return 0;
    }
    
    // 检查设备是否在白名单中
    if (is_dev_allowed(dev)) {
        bbguard_verbose("device %u:%u in allowlist, deferring to SELinux\n", 
               MAJOR(dev), MINOR(dev));
        return 0;
    }
    
    // 检查进程域是否在白名单中
    context = get_current_security_context();
    if (context) {
        if (is_domain_allowed(context)) {
            bbguard_verbose("domain %s in allowlist, deferring to SELinux\n", context);
            security_release_secctx(context, strlen(context));
            return 0;
        }
        security_release_secctx(context, strlen(context));
    } else {
        bbguard_verbose("no security context available\n");
    }
    
    // 记录拒绝日志（限流）
    if (should_log_denial(dev)) {
        pr_warn_ratelimited("baseband_guard: denied ioctl %u to block device %u:%u, process=%s\n",
                   cmd, MAJOR(dev), MINOR(dev), current->comm);
    }
    
    return -EPERM;
}

// 兼容性 ioctl 检查钩子（6.6+）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int bbguard_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
    return bbguard_file_ioctl(file, cmd, arg);
}
#endif

// 挂载钩子 - 检测 /data 挂载
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int bbguard_sb_mount(const struct path *dev_path, const struct path *path,
               const char *type, unsigned long flags, void *data)
#else
static int bbguard_sb_mount(struct path *dev_path, struct path *path,
               const char *type, unsigned long flags, void *data)
#endif
{
    const char *mountpoint;
    
    if (atomic_read(&armed))
        return 0;
    
    mountpoint = path->dentry->d_name.name;
    if (mountpoint && strcmp(mountpoint, "data") == 0) {
        bbguard_verbose("data mounted, checking arming conditions\n");
        check_arming_conditions();
    }
    
    return 0;
}

// Zygote 候选路径
static const char *zygote_candidates[] = {
    "/system/bin/app_process64",
    "/system/bin/app_process32",
    "/apex/com.android.art/bin/app_process64",
    "/apex/com.android.art/bin/app_process32",
};

// 执行程序钩子 - 检测 Zygote
static int bbguard_bprm_check_security(struct linux_binprm *bprm)
{
    const char *filename;
    size_t i;
    
    if (atomic_read(&armed))
        return 0;
    
    filename = bprm->filename;
    if (!filename)
        return 0;
    
    for (i = 0; i < ARRAY_SIZE(zygote_candidates); i++) {
        if (strcmp(filename, zygote_candidates[i]) == 0) {
            bbguard_verbose("zygote detected, checking arming conditions\n");
            check_arming_conditions();
            break;
        }
    }
    
    return 0;
}

// 延迟激活保护（确保 SELinux 已进入 Enforcing 模式）
static void delayed_arm_work(struct work_struct *work)
{
    int i;
    
    // 等待 SELinux 进入 Enforcing 模式
    for (i = 0; i < 100; i++) {
        if (is_selinux_enforcing()) {
            bbguard_verbose("SELinux is now enforcing, arming protection\n");
            check_arming_conditions();
            return;
        }
        msleep(100);
    }
    
    bbguard_verbose("Timeout waiting for SELinux to enter enforcing mode\n");
}

static DECLARE_DELAYED_WORK(delayed_arm_work_struct, delayed_arm_work);

// LSM 钩子定义
static struct security_hook_list bbguard_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(file_permission, bbguard_file_permission),
    LSM_HOOK_INIT(file_ioctl, bbguard_file_ioctl),
    LSM_HOOK_INIT(sb_mount, bbguard_sb_mount),
    LSM_HOOK_INIT(bprm_check_security, bbguard_bprm_check_security),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    LSM_HOOK_INIT(file_ioctl_compat, bbguard_file_ioctl_compat),
#endif
};

// 初始化函数
static int __init bbguard_init(void)
{
    bbguard_verbose("initializing\n");
    
    // 注册 LSM 钩子
    security_add_hooks(bbguard_hooks, ARRAY_SIZE(bbguard_hooks), "baseband_guard");
    
    // 安排延迟工作，确保 SELinux 已进入 Enforcing 模式
    schedule_delayed_work(&delayed_arm_work_struct, msecs_to_jiffies(5000));
    
    bbguard_verbose("initialized (slot_suffix=%s)\n", slot_suffix ? slot_suffix : "none");
    return 0;
}

// 清理函数
static void __exit bbguard_exit(void)
{
    cancel_delayed_work_sync(&delayed_arm_work_struct);
}

// 延迟初始化（确保所有依赖已加载）
late_initcall(bbguard_init);
module_exit(bbguard_exit);

// 模块信息
MODULE_DESCRIPTION("Baseband/Bootloader partition write guard LSM");
MODULE_LICENSE("GPL v2");