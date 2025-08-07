#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

/*
 * 1. 唯一明文 16 字节 SN 区块
 *    - .data.expected_sn 段，不会被Clang/GCC合并/优化/丢弃
 *    - 支持后期 hex 编辑直接替换
 */
__attribute__((section(".data.expected_sn")))
__attribute__((used))
const char EXPECTED_SN[16] = "1217280837\0\0\0\0\0\0"; // 只用前10位，其余补0

/*
 * 2. 检查线程，延迟2分钟后校验
 */
static int serialid_checker_thread(void *data)
{
    msleep(2 * 60 * 1000);

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
        // 去掉末尾 \n
        if (buf[ret - 1] == '\n')
            buf[ret - 1] = '\0';

        // 比较前10位
        if (strncmp(buf, EXPECTED_SN, 10) != 0) {
            // HEX debug输出，方便核查
            pr_emerg("SOC_SN_CHECK: mismatch!\n"
                     "  got      : %s\n"
                     "  expected : %.10s\n"
                     "  got HEX  : %*phC\n"
                     "  exp HEX  : %*phC\n",
                     buf, EXPECTED_SN, 10, buf, 10, EXPECTED_SN);
            panic("SOC serial number check failed!\n");
        }
        pr_info("SOC_SN_CHECK: OK, serial matched: %s\n", buf);
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
    }
    return 0;
}

/*
 * 3. late_initcall 自动启动
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
