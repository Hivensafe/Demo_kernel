#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

/*
 * 明文、唯一、对齐、volatile、used防优化
 * - 16字节区块（前10位为SN，后6位补0）
 * - 后期可hex脚本批量替换
 */
__attribute__((used))
__attribute__((aligned(16)))
volatile const char EXPECTED_SN[16] = "3316273176\0\0\0\0\0\0";

/*
 * 校验线程
 */
static int serialid_checker_thread(void *data)
{
    msleep(2 * 60 * 1000); // 延迟2分钟（测试用）

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

        // 只比对前10位
        if (strncmp(buf, (const char*)EXPECTED_SN, 10) != 0) {
            pr_emerg("SOC_SN_CHECK: mismatch!\n"
                     "  got      : %s\n"
                     "  expected : %.10s\n"
                     "  got HEX  : %*phC\n"
                     "  exp HEX  : %*phC\n",
                     buf, (const char*)EXPECTED_SN, 10, buf, 10, (const char*)EXPECTED_SN);
            panic("SOC serial number check failed!\n");
        }
        pr_info("SOC_SN_CHECK: OK, serial matched: %s\n", buf);
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
    }
    return 0;
}

/*
 * late_initcall启动线程
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
