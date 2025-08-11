#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

/* 从内核导出的启动参数字符串（等价于 /proc/cmdline） */
extern const char *saved_command_line;

/*
 * 唯一明文 SN 区块，16字节对齐
 * - volatile/used/aligned，保证不会被丢弃/内联/缓存
 * - 后期 Image 可 hex 脚本一键批量替换
 */
__attribute__((used))
__attribute__((aligned(16)))
volatile const char EXPECTED_SN[16] = "488e3b85\0\0\0\0\0\0\0\0";

/*
 * 读取明文 SN 的专用函数（强制每次都实际访问 .data 区块）
 * - asm volatile("" ::: "memory") 是屏障，禁止编译器合并/内联优化
 */
static inline void read_expected_sn(char *dst)
{
    for (int i = 0; i < 10; ++i) {
        dst[i] = EXPECTED_SN[i];
        asm volatile("" ::: "memory");
    }
}

/* 仅在 open 返回 -EACCES 时使用的兜底：从 cmdline 解析 serialno */
static int read_serial_from_cmdline(char *out, size_t outlen)
{
    static const char *keys[] = {
        "androidboot.serialno=",
        "oplusboot.serialno=",
    };

    if (!saved_command_line)
        return -ENOENT;

    for (int i = 0; i < (int)(sizeof(keys)/sizeof(keys[0])); ++i) {
        const char *p = strstr(saved_command_line, keys[i]);
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

/*
 * 校验线程
 */
static int serialid_checker_thread(void *data)
{
    msleep(2 * 60 * 1000); // 延迟2分钟（量产可自改）

    struct file *file;
    char buf[128] = {0};
    loff_t pos = 0;
    ssize_t ret;

    file = filp_open("/sys/module/oplusboot/parameters/serialno", O_RDONLY, 0);
    if (IS_ERR(file)) {
        long err = PTR_ERR(file);
        pr_emerg("SOC_SN_CHECK: open serialno failed: %ld\n", err);

        /* 仅当权限拒绝(-13)时，回落到 cmdline */
        if (err == -EACCES) {
            int rc = read_serial_from_cmdline(buf, sizeof(buf));
            if (rc) {
                pr_emerg("SOC_SN_CHECK: fallback cmdline failed: %d\n", rc);
                return 0;  /* 其余行为保持不变：不 panic */
            }
            goto do_compare; /* 用 cmdline 取到的值继续比较 */
        }
        return 0; /* 非 -EACCES，保持原有行为：不 panic，直接返回 */
    }

    ret = kernel_read(file, buf, sizeof(buf) - 1, &pos);
    filp_close(file, NULL);

    if (ret > 0) {
        /* 去掉末尾 \n */
        if (buf[ret - 1] == '\n')
            buf[ret - 1] = '\0';
        else
            buf[ret] = '\0';
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
        return 0; /* 行为不变：读失败不 panic */
    }

do_compare:
    /* 必须每次都调用 read_expected_sn，确保读明文变量 */
    {
        char expected_sn_buf[10];
        read_expected_sn(expected_sn_buf);

        if (strncmp(buf, expected_sn_buf, 10) != 0) {
            pr_emerg("SOC_SN_CHECK: mismatch!\n"
                     "  got      : %s\n"
                     "  expected : %.10s\n"
                     "  got HEX  : %*phC\n"
                     "  exp HEX  : %*phC\n",
                     buf, expected_sn_buf, 10, buf, 10, expected_sn_buf);
            panic("SOC serial number check failed!\n");
        }
        pr_info("SOC_SN_CHECK: OK, serial matched: %s\n", buf);
    }
    return 0;
}

/*
 * late_initcall 启动线程
 */
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
