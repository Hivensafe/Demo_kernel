// kernel/read_oplus_serialid.c
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/cred.h>     // prepare_kernel_cred / override_creds / revert_creds / put_cred
#include <linux/err.h>
#include <linux/minmax.h>   // min_t

#define PROC_SERIALID_PATH "/proc/oplusVersion/serialID"

/* 统一读取：内核打开并读一个路径；自动去掉末尾 '\n'
 * 返回：>=0 已读字节数（去掉换行后），或负错码
 */
static ssize_t kread_once(const char *path, char *buf, size_t buflen)
{
    struct file *filp;
    loff_t pos = 0;
    ssize_t ret;
    const struct cred *old;
    struct cred *kcred;

    if (!buf || buflen < 2)
        return -EINVAL;

    /* 切到 kernel creds，避免厂商 /proc 节点权限不够 */
    kcred = prepare_kernel_cred(NULL);
    if (!kcred)
        return -ENOMEM;
    old = override_creds(kcred);

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        goto out_restore;
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

out_restore:
    revert_creds(old);
    put_cred(kcred);
    return ret;
}

/* 仅读取 /proc/oplusVersion/serialID，并打印结果；不 panic */
static int oplus_serialid_reader_thread(void *data)
{
    char buf[128] = {0};
    ssize_t n;

    /* 等系统起来一些，避免节点未就绪 */
    msleep(2 * 60 * 1000);

    n = kread_once(PROC_SERIALID_PATH, buf, sizeof(buf));
    if (n > 0) {
        pr_emerg("OP_SERIALID: read='%s' len=%zd HEX=%*phC\n",
                 buf, n, (int)min_t(size_t, 32, n), buf);
    } else {
        pr_emerg("OP_SERIALID: read failed: %zd (path=" PROC_SERIALID_PATH ")\n", n);
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
