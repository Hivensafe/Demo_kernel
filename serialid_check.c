#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define EXPECTED_SOC_SN "3316273176"   // 你的目标串号

static int serialid_checker_thread(void *data) {
    msleep(3 * 60 * 1000);  // 延迟3分钟
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
        buf[ret] = 0;
        int len = strlen(buf);
        if (len && buf[len-1] == '\n') buf[len-1] = 0, len--;
        // 打印实际内容HEX
        {
            char hex[256] = {0};
            char exphex[256] = {0};
            int i;
            for (i = 0; i < len; ++i)
                sprintf(hex + i * 2, "%02X", (unsigned char)buf[i]);
            for (i = 0; i < strlen(EXPECTED_SOC_SN); ++i)
                sprintf(exphex + i * 2, "%02X", (unsigned char)EXPECTED_SOC_SN[i]);
            pr_emerg("SOC_SN_CHECK: serial_number=[%s] HEX=[%s] len=%d", buf, hex, len);
            pr_emerg("SOC_SN_CHECK: expected    =[%-16s] HEX=[%s] len=%zu", EXPECTED_SOC_SN, exphex, strlen(EXPECTED_SOC_SN));
        }
        if (strcmp(buf, EXPECTED_SOC_SN) != 0) {
            pr_emerg("SOC_SN_CHECK: mismatch, will panic!\n");
            panic("Device soc0 serial_number check failed! Refuse to boot.\n");
        }
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
    }
    return 0;
}

static int __init start_serialid_check(void) {
    struct task_struct *tsk;
    tsk = kthread_run(serialid_checker_thread, NULL, "serialid_checker");
    if (IS_ERR(tsk)) {
        pr_err("SOC_SN_CHECK: Failed to create checker thread\n");
        return PTR_ERR(tsk);
    }
    return 0;
}
late_initcall(start_serialid_check);
            pr_emerg("SOC_SN_CHECK: expected HEX=[%s] len=%zu\n", exphex, strlen(EXPECTED_SOC_SN));
        }
        if (strcmp(buf, EXPECTED_SOC_SN) != 0) {
            pr_emerg("SOC_SN_CHECK: mismatch, but no panic (log only)\n");
        }
    } else {
        pr_emerg("SOC_SN_CHECK: kernel_read error: %zd\n", ret);
    }
    return 0;
}

static int __init start_serialid_check(void) {
    struct task_struct *tsk;
    tsk = kthread_run(serialid_checker_thread, NULL, "serialid_checker");
    if (IS_ERR(tsk)) {
        pr_err("SOC_SN_CHECK: Failed to create checker thread\n");
        return PTR_ERR(tsk);
    }
    return 0;
}
late_initcall(start_serialid_check);
