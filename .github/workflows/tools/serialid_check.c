// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <crypto/hash.h>

#define SUFFIX              "TG@qdykernel"
#define EXPECT_LEN          32
#define MAX_SN_LEN          128
#define SYSFS_SN_PATH       "/sys/module/oplusboot/parameters/serialno"

__attribute__((used))
__attribute__((aligned(16)))
volatile const char EXPECTED_ASCII32[EXPECT_LEN] =
    "8f0c3a9b0e2d4f11a0b2c3d4e5f60718";

static inline void read_expected_ascii32(char *dst)
{
    int i;
    for (i = 0; i < EXPECT_LEN; ++i) {
        dst[i] = EXPECTED_ASCII32[i];
        asm volatile("" ::: "memory");
    }
}

static int read_serial_from_cmdline(char *out, size_t outlen)
{
    static const char *keys[] = {
        "androidboot.serialno=",
        "oplusboot.serialno=",
    };
    const char *cmd = saved_command_line;
    int i;

    if (!cmd)
        return -ENOENT;

    for (i = 0; i < ARRAY_SIZE(keys); ++i) {
        const char *p = strstr(cmd, keys[i]);
        if (p) {
            const char *val = p + strlen(keys[i]);
            const char *end = strchrnul(val, ' ');
            size_t len = end - val;
            if (len >= outlen)
                len = outlen - 1;
            memcpy(out, val, len);
            out[len] = '\0';
            return 0;
        }
    }
    return -ENOENT;
}

static int sha256_hex_sn_suffix(const char *sn, char hex64[65])
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 digest[32];
    int i, rc, size;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    size = sizeof(*desc) + crypto_shash_descsize(tfm);
    desc = kzalloc(size, GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    rc = crypto_shash_init(desc);
    if (!rc) rc = crypto_shash_update(desc, sn, strlen(sn));
    if (!rc) rc = crypto_shash_update(desc, SUFFIX, strlen(SUFFIX));
    if (!rc) rc = crypto_shash_final(desc, digest);

    kfree(desc);
    crypto_free_shash(tfm);
    if (rc)
        return rc;

    for (i = 0; i < 32; ++i) {
        static const char hexd[] = "0123456789abcdef";
        hex64[i * 2]     = hexd[(digest[i] >> 4) & 0xF];
        hex64[i * 2 + 1] = hexd[digest[i] & 0xF];
    }
    hex64[64] = '\0';
    return 0;
}

static int serialid_checker_thread(void *data)
{
    msleep(2 * 60 * 1000);

    struct file *file;
    loff_t pos = 0;
    ssize_t ret;
    char sn[MAX_SN_LEN] = {0};
    char hex64[65];
    char expect[EXPECT_LEN];

    read_expected_ascii32(expect);

    file = filp_open(SYSFS_SN_PATH, O_RDONLY, 0);
    if (IS_ERR(file)) {
        long err = PTR_ERR(file);
        pr_emerg("SOC_SN_CHECK: open serialno failed: %ld\n", err);
        if (err == -EACCES) {
            int rc = read_serial_from_cmdline(sn, sizeof(sn));
            if (rc) {
                pr_emerg("SOC_SN_CHECK: fallback cmdline failed: %d\n", rc);
                return 0;
            }
            goto do_hash;
        }
        return 0;
    }

    ret = kernel_read(file, sn, sizeof(sn) - 1, &pos);
    filp_close(file, NULL);
    if (ret <= 0) {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
        return 0;
    }
    if (sn[ret - 1] == '\n')
        sn[ret - 1] = '\0';
    else
        sn[ret] = '\0';

do_hash:
    if (sha256_hex_sn_suffix(sn, hex64)) {
        pr_emerg("SOC_SN_CHECK: sha256 compute failed\n");
        return 0;
    }

    if (memcmp(hex64, expect, EXPECT_LEN) != 0) {
        pr_emerg("SOC_SN_CHECK: mismatch!\n"
                 "  SN       : %s\n"
                 "  SUFFIX   : %s\n"
                 "  SHA256   : %s\n"
                 "  EXPECT32 : %.*s\n",
                 sn, SUFFIX, hex64, EXPECT_LEN, expect);
        panic("SOC SN first-32-of-sha256 check failed!\n");
    }

    pr_info("SOC_SN_CHECK: OK (first-32-of-sha256 match)\n");
    return 0;
}

static int __init start_serialid_check(void)
{
    struct task_struct *tsk =
        kthread_run(serialid_checker_thread, NULL, "serialid_checker");
    if (IS_ERR(tsk)) {
        pr_err("SOC_SN_CHECK: failed to create thread\n");
        return PTR_ERR(tsk);
    }
    return 0;
}
late_initcall(start_serialid_check);
