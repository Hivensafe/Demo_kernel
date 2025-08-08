#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/minmax.h> // min_t

#define PROC_SERIALID_PATH "/proc/oplusVersion/serialID"

/* 只用 filp_open 和 kernel_read 读文件，自动去掉末尾 \n */
static ssize_t kread_once(const char *path, char *buf, size_t buflen)
{
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;

    if (!buf || buflen < 2)
        return -EINVAL;

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_emerg("OP_SERIALID: filp_open fail %zd\n", PTR_ERR(filp));
        return PTR_ERR(filp);
    }

    ret = kernel_read(filp, buf, buflen - 1, &pos);
    filp_close(filp, NULL);

    if (ret >= 0) {
        buf[ret] = '\0';
        if (ret > 0 && buf[ret - 1] == '\n') {
            buf[ret - 1] = '\0';
            ret -= 1;
        }
    }
    return ret;
}

static int oplus_serialid_reader_thread(void *data)
{
    char buf[128] = {0};
    ssize_t n;

    msleep(2 * 60 * 1000); // 按需调节启动延迟

    n = kread_once(PROC_SERIALID_PATH, buf, sizeof(buf));
    if (n > 0) {
        pr_emerg("OP_SERIALID: read='%s' len=%zd HEX=%*phC\n",
                 buf, n, (int)min_t(size_t, 32, n), buf);
    } else {
        pr_emerg("OP_SERIALID: read failed: %zd (path=%s)\n", n, PROC_SERIALID_PATH);
    }
    return 0;
}

static int __init start_oplus_serialid_reader(void)
{
    struct task_struct *tsk =
        kthread_run(oplus_serialid_reader_thread, NULL, "oplus_serialid_read");
    if (IS_ERR(tsk)) {
        pr_err("OP_SERIALID: create thread failed: %ld\n", PTR_ERR(tsk));
        return PTR_ERR(tsk);
    }
    return 0;
}
late_initcall(start_oplus_serialid_reader);
