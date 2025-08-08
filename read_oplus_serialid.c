#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/minmax.h>

#define PROC_SERIALID_PATH "/proc/oplusVersion/serialID"

static ssize_t kread_once(const char *path, char *buf, size_t buflen)
{
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;

    pr_emerg("OP_SERIALID: >>> Try filp_open '%s'\n", path);

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_emerg("OP_SERIALID: !!! filp_open failed, ret=%zd\n", PTR_ERR(filp));
        return PTR_ERR(filp);
    }
    pr_emerg("OP_SERIALID: filp_open success, file ptr=%px\n", filp);

    pr_emerg("OP_SERIALID: >>> Call kernel_read...\n");
    ret = kernel_read(filp, buf, buflen - 1, &pos);

    if (ret < 0) {
        pr_emerg("OP_SERIALID: !!! kernel_read failed, ret=%zd\n", ret);
    } else {
        pr_emerg("OP_SERIALID: kernel_read success, got %zd bytes\n", ret);
        buf[ret] = '\0';
        if (ret > 0 && buf[ret - 1] == '\n') {
            buf[ret - 1] = '\0';
            pr_emerg("OP_SERIALID: Trimmed ending \\n\n");
            ret -= 1;
        }
    }
    filp_close(filp, NULL);

    return ret;
}

static int oplus_serialid_reader_thread(void *data)
{
    char buf[128] = {0};
    ssize_t n;

    pr_emerg("OP_SERIALID: === Thread started, sleep 2min ===\n");
    msleep(2 * 60 * 1000);

    pr_emerg("OP_SERIALID: === Wake up, about to read %s ===\n", PROC_SERIALID_PATH);

    n = kread_once(PROC_SERIALID_PATH, buf, sizeof(buf));
    if (n > 0) {
        pr_emerg("OP_SERIALID: FINAL: read='%s' len=%zd HEX=%*phC\n",
                 buf, n, (int)min_t(size_t, 32, n), buf);
    } else {
        pr_emerg("OP_SERIALID: FINAL: read failed: %zd (path=%s)\n", n, PROC_SERIALID_PATH);
    }

    pr_emerg("OP_SERIALID: === Thread finished ===\n");
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
