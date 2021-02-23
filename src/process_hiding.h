#ifndef LKM_TLSKIT_PROCESS_HIDING_H
#define LKM_TLSKIT_PROCESS_HIDING_H

/**
 * Enable process hiding
 */
int enable_process_hiding(void);

/**
 * Disable process hiding
 */
void disable_process_hiding(void);

/**
 * Check if name is a hidden process
 * @param name
 * @return 0 if not, 1 if it is
 */
int check_hidden_process(const char *name);

/**
 * Add a pid, which should be hidden
 * @param pid
 * @return 0 on success, -1 else
 */
int hide_process_add(pid_t pid);

/**
 * Remove a pid from hidden pids
 * @param pid
 * @return 0 on success, -1 else
 */
int hide_process_rm(pid_t pid);

#endif //LKM_TLSKIT_PROCESS_HIDING_H
