#ifndef LKM_TLSKIT_SHARED_H
#define LKM_TLSKIT_SHARED_H

#ifndef __KERNEL__
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

/*
 * IOCTl commands
 */
#define RKCTL_PING      _IO('@', 0x01)
#define RKCTL_UNLOAD    _IO('@', 0x02)

#define PROC_ENTRY_NAME "tlskit"
#define IOCTL_FILE_PATH "/proc/tlskit"
#define MODULE_NAME     "tlskit"

#endif //LKM_TLSKIT_SHARED_H
