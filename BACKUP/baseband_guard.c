// SPDX-License-Identifier: GPL-2.0
/*
 * baseband_guard: LSM to deny actual writes to critical baseband/bootloader partitions
 * - Deny at write-time (file_permission with MAY_WRITE), NOT at open-time
 * - No timers, no directory walks, no <linux/genhd.h>
 * - On-demand initial build via lookup_bdev(path, &dev_t)
 * - Late /dev/block/by-name nodes handled by throttled retries on cache miss
 * - Verbose logs per name: [OK]/[MISS] at initial build; [RETRY-OK] on later success
 * - First write also denied via DEV-MATCH fallback: reverse match current inode->i_rdev
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>        /* MAY_* */
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/blkdev.h>    /* lookup_bdev */
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/jiffies.h>

extern char *saved_command_line; /* from init/main.c */

#define BB_ENFORCING 1

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_ALLOW_IN_RECOVERY
#define BB_ALLOW_IN_RECOVERY 1
#else
#define BB_ALLOW_IN_RECOVERY 0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_PROTECT_BOOTIMG
#define BB_PROTECT_BOOTIMG 1
#else
#define BB_PROTECT_BOOTIMG 0
#endif

#ifdef CONFIG_SECURITY_BASEBAND_GUARD_VERBOSE
#define BB_VERBOSE 1
#else
#define BB_VERBOSE 0
#endif

#define BB_BYNAME_DIR "/dev/block/by-name"

/* ======== 受保护分区清单 ======== */
struct name_entry { const char *name; u8 st; };
enum res_state { RS_UNKNOWN = 0, RS_OK = 1, RS_FAIL = 2 };

static struct name_entry core_names[] = {
  { "xbl", RS_UNKNOWN }, { "xbl_config", RS_UNKNOWN }, { "uefi", RS_UNKNOWN },
  { "uefisecapp", RS_UNKNOWN }, { "abl", RS_UNKNOWN },
  { "modem", RS_UNKNOWN }, { "modemst1", RS_UNKNOWN }, { "modemst2", RS_UNKNOWN },
  { "fsg", RS_UNKNOWN }, { "fsc", RS_UNKNOWN }, { "connsec", RS_UNKNOWN },
  { "mdm1oemnvbktmp", RS_UNKNOWN }, { "oplusdycnvbk", RS_UNKNOWN }, { "oplusstanvbk", RS_UNKNOWN },
  { "nvram", RS_UNKNOWN }, { "nvdata", RS_UNKNOWN }, { "nvcfg", RS_UNKNOWN },
  { "md_sec", RS_UNKNOWN }, { "sec1", RS_UNKNOWN }, { "seccfg", RS_UNKNOWN },
  { "vbmeta", RS_UNKNOWN }, { "vbmeta_system", RS_UNKNOWN }, { "vbmeta_vendor", RS_UNKNOWN },
  { "tz", RS_UNKNOWN }, { "hyp", RS_UNKNOWN }, { "keymaster", RS_UNKNOWN }, { "keystore", RS_UNKNOWN },
  { "storsec", RS_UNKNOWN }, { "secdata", RS_UNKNOWN }, { "ssd", RS_UNKNOWN },
  { "pvmfw", RS_UNKNOWN }, { "vm-bootsys", RS_UNKNOWN }, { "vm-persist", RS_UNKNOWN },
  { "imagefv", RS_UNKNOWN }, { "toolsfv", RS_UNKNOWN }, { "tee", RS_UNKNOWN }, { "rotfw", RS_UNKNOWN },
  { "frp", RS_UNKNOWN }, { "preloader_raw", RS_UNKNOWN }, { "lk", RS_UNKNOWN },
  { "bootloader1", RS_UNKNOWN }, { "bootloader2", RS_UNKNOWN }, { "ocdt", RS_UNKNOWN },
};
static const size_t core_names_cnt = ARRAY_SIZE(core_names);

/* ======== 受保护 dev_t 缓存 ======== */
struct bbg_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(bbg_protected_devs, 7); /* 128 buckets */
static bool bbg_cache_built;             /* 首次构建完成标志 */

/* 按需重试的软节流（无定时器） */
static unsigned long bbg_retry_jiffies;                  /* 上次重试时间 */
static const unsigned long bbg_retry_min_interval = HZ/5;/* 约 200ms */

/* ======== 帮助函数 ======== */
static bool in_recovery_mode(void)
{
#if BB_ALLOW_IN_RECOVERY
  if (!saved_command_line) return false;
  if (strstr(saved_command_line, "androidboot.mode=recovery")) return true;
#endif
  return false;
}

static bool cache_has(dev_t dev)
{
  struct bbg_node *p;
  hash_for_each_possible(bbg_protected_devs, p, h, (u64)dev)
    if (p->dev == dev) return true;
  return false;
}

static void cache_add(dev_t dev)
{
  struct bbg_node *n;
  if (!dev || cache_has(dev)) return;
  n = kmalloc(sizeof(*n), GFP_KERNEL);
  if (!n) return;
  n->dev = dev;
  hash_add(bbg_protected_devs, &n->h, (u64)dev);
#if BB_VERBOSE
  pr_info("baseband_guard: protect dev %u:%u\n", MAJOR(dev), MINOR(dev));
#endif
}

/* 6.6: lookup_bdev(path, &dev_t) */
static bool resolve_byname_dev(const char *name, dev_t *out)
{
  char *path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
  dev_t dev; int ret;
  if (!path) return false;
  ret = lookup_bdev(path, &dev);
  kfree(path);
  if (ret) return false;
  *out = dev;
  return true;
}

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

/* 初次构建：解析清单；失败项记为 RS_FAIL（打印 [MISS]），成功打印 [OK] */
static void build_cache_once(void)
{
  const char *suf = slot_suffix_from_cmdline(); /* "_a"/"_b"/NULL */
  size_t i; dev_t dev;

  if (READ_ONCE(bbg_cache_built))
    return;

  for (i = 0; i < core_names_cnt; i++) {
    const char *n = core_names[i].name;
    bool ok = false;

    /* 基本名 */
    if (resolve_byname_dev(n, &dev)) { cache_add(dev); ok = true; }

    /* A/B 后缀 */
    if (suf) {
      char *nm = kasprintf(GFP_KERNEL, "%s%s", n, suf);
      if (nm) { if (resolve_byname_dev(nm, &dev)) { cache_add(dev); ok = true; } kfree(nm); }
    } else {
      char *na = kasprintf(GFP_KERNEL, "%s_a", n);
      char *nb = kasprintf(GFP_KERNEL, "%s_b", n);
      if (na) { if (resolve_byname_dev(na, &dev)) { cache_add(dev); ok = true; } kfree(na); }
      if (nb) { if (resolve_byname_dev(nb, &dev)) { cache_add(dev); ok = true; } kfree(nb); }
    }

    core_names[i].st = ok ? RS_OK : RS_FAIL;

#if BB_VERBOSE
    if (ok)
      pr_info("baseband_guard: [OK]   %s protected\n", n);
    else
      pr_info("baseband_guard: [MISS] %s not found (RS_FAIL)\n", n);
#endif
  }

  WRITE_ONCE(bbg_cache_built, true);

#if BB_VERBOSE
  {
    int cnt = 0; unsigned bkt; struct bbg_node *p;
    hash_for_each(bbg_protected_devs, bkt, p, h) cnt++;
    pr_info("baseband_guard: cache built, protected=%d\n", cnt);
  }
#endif
}

/* 对 RS_FAIL 的名字做一轮重试；基于 jiffies 的最小间隔（无定时器） */
static void retry_resolve_failed_names_throttled(void)
{
  const char *suf = slot_suffix_from_cmdline();
  size_t i; dev_t dev; bool any = false;

  if (time_before(jiffies, READ_ONCE(bbg_retry_jiffies) + bbg_retry_min_interval))
    return;

  for (i = 0; i < core_names_cnt; i++) {
    if (core_names[i].st != RS_FAIL) continue;
    {
      const char *n = core_names[i].name;
      bool ok = false;

      if (resolve_byname_dev(n, &dev)) { cache_add(dev); ok = true; }

      if (!ok && suf) {
        char *nm = kasprintf(GFP_KERNEL, "%s%s", n, suf);
        if (nm) { if (resolve_byname_dev(nm, &dev)) { cache_add(dev); ok = true; } kfree(nm); }
      }
      if (!ok) {
        char *na = kasprintf(GFP_KERNEL, "%s_a", n);
        char *nb = kasprintf(GFP_KERNEL, "%s_b", n);
        if (na) { if (resolve_byname_dev(na, &dev)) { cache_add(dev); ok = true; } kfree(na); }
        if (nb) { if (resolve_byname_dev(nb, &dev)) { cache_add(dev); ok = true; } kfree(nb); }
      }

      if (ok) {
        core_names[i].st = RS_OK; any = true;
#if BB_VERBOSE
        pr_info("baseband_guard: [RETRY-OK] %s protected\n", n);
#endif
      }
    }
  }

  WRITE_ONCE(bbg_retry_jiffies, jiffies);
#if BB_VERBOSE
  pr_info("baseband_guard: retry pass done%s\n", any ? " (some added)" : "");
#endif
}

static int deny(const char *why)
{
  if (!BB_ENFORCING) return 0;
  if (BB_ALLOW_IN_RECOVERY && in_recovery_mode()) return 0;
#if BB_VERBOSE
  pr_info("baseband_guard: deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
#endif
  return -EPERM;
}

/* 破坏性 ioctl：仅用于受保护分区 */
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

/* ========= LSM Hooks =========
 * 只在写路径拒绝：避免 O_RDWR 只读访问受影响（例如调制解调器初始化）
 */
static int bb_file_permission(struct file *file, int mask)
{
  struct inode *inode;
  size_t i;

  if (!(mask & MAY_WRITE))    /* 只拦真正的写操作 */
    return 0;
  if (!file)
    return 0;

  inode = file_inode(file);
  if (!S_ISBLK(inode->i_mode))
    return 0;

  /* 首次需要时构建缓存 */
  if (!READ_ONCE(bbg_cache_built))
    build_cache_once();

  /* 命中：拒绝 */
  if (cache_has(inode->i_rdev))
    return deny("write to protected partition");

  /* ===== A) DEV-MATCH 兜底：首写也能挡 =====
   * 反向用当前 inode->i_rdev 去匹配 core_names[]（含 _a/_b 变体）的实际 dev_t。
   * 命中则当场加入缓存并拒绝本次写。
   */
  {
    const char *suf = slot_suffix_from_cmdline();
    dev_t d;
    for (i = 0; i < core_names_cnt; i++) {
      const char *n = core_names[i].name;
      bool hit = false;

      if (resolve_byname_dev(n, &d) && d == inode->i_rdev) hit = true;
      if (!hit && suf) {
        char *nm = kasprintf(GFP_KERNEL, "%s%s", n, suf);
        if (nm) { if (resolve_byname_dev(nm, &d) && d == inode->i_rdev) hit = true; kfree(nm); }
      } else if (!hit) {
        char *na = kasprintf(GFP_KERNEL, "%s_a", n);
        char *nb = kasprintf(GFP_KERNEL, "%s_b", n);
        if (na) { if (resolve_byname_dev(na, &d) && d == inode->i_rdev) hit = true; kfree(na); }
        if (!hit && nb) { if (resolve_byname_dev(nb, &d) && d == inode->i_rdev) hit = true; kfree(nb); }
      }

      if (hit) {
        cache_add(inode->i_rdev);
#if BB_VERBOSE
        pr_info("baseband_guard: [DEV-MATCH] protect current dev %u:%u as %s\n",
                MAJOR(inode->i_rdev), MINOR(inode->i_rdev), n);
#endif
        return deny("write to protected partition (dev match)");
      }
    }
  }

  /* B) 未命中：按需重试（处理 by-name 迟到） */
  if (READ_ONCE(bbg_cache_built))
    retry_resolve_failed_names_throttled();

  /* 重试后再判一次 */
  if (cache_has(inode->i_rdev))
    return deny("write to protected partition (after retry)");

  return 0;
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  struct inode *inode;

  if (!file)
    return 0;
  inode = file_inode(file);
  if (!S_ISBLK(inode->i_mode))
    return 0;

  /* 构建/补全缓存（当首次命中 ioctl 的是延迟节点时也能覆盖到） */
  if (!READ_ONCE(bbg_cache_built))
    build_cache_once();
  else
    retry_resolve_failed_names_throttled();

  /* 仅在受保护分区上拦破坏性 ioctl */
  if (cache_has(inode->i_rdev) && is_destructive_ioctl(cmd))
    return deny("destructive ioctl on protected partition");

  return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
  return bb_file_ioctl(file, cmd, arg);
}
#endif

static struct security_hook_list bb_hooks[] = {
  LSM_HOOK_INIT(file_permission, bb_file_permission),
  LSM_HOOK_INIT(file_ioctl,      bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
  LSM_HOOK_INIT(file_ioctl_compat, bb_file_ioctl_compat),
#endif
};

static int __init bb_init(void)
{
  security_add_hooks(bb_hooks, ARRAY_SIZE(bb_hooks), "baseband_guard");
#if BB_VERBOSE
  pr_info("baseband_guard: init (write-time only; throttled retry on miss + DEV-MATCH fallback)\n");
#endif
  return 0;
}

DEFINE_LSM(baseband_guard) = {
  .name = "baseband_guard",
  .init = bb_init,
};

MODULE_DESCRIPTION("LSM to guard baseband/bootloader partitions (deny at write-time; on-demand build + throttled retry + dev match fallback)");
MODULE_AUTHOR("秋刀鱼");
MODULE_LICENSE("GPL v2");
