/* kernel/soc_serial_chk.c */
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

static const char __aligned(16) EXPECTED_SN[16] =
        "3316273176\0\0\0\0\0\0";   /* 只用前 10 字节，后6字节补0 */

static int serialid_checker_thread(void *data)
{
    msleep(3 * 60 * 1000);  // 延迟 3 分钟
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
        if (buf[ret-1] == '\n') buf[ret-1] = '\0';
        if (strncmp(buf, EXPECTED_SN, 10) != 0) {
            pr_emerg("SOC_SN_CHECK: mismatch!\n got      : %s\n expected : %.10s\n", buf, EXPECTED_SN);
            panic("SOC serial number check failed!\n");
        }
        pr_info("SOC_SN_CHECK: OK\n");
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
    }
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
