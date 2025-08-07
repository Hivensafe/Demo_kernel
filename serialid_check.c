#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

/*
 * 唯一明文 SN 区块，16字节对齐
 * - volatile/used/aligned，保证不会被丢弃/内联/缓存
 * - 后期Image可hex脚本一键批量替换
 */
__attribute__((used))
__attribute__((aligned(16)))
volatile const char EXPECTED_SN[16] = "3316273176\0\0\0\0\0\0";

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

    file = filp_open("/sys/devices/soc0/serial_number", O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_emerg("SOC_SN_CHECK: open serial_number failed: %ld\n", PTR_ERR(file));
        return 0;
    }

    ret = kernel_read(file, buf, sizeof(buf) - 1, &pos);
    filp_close(file, NULL);

    if (ret > 0) {
        // 去掉末尾\n
        if (buf[ret - 1] == '\n')
            buf[ret - 1] = '\0';

        // 必须每次都调用 read_expected_sn，确保读明文变量
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
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
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
