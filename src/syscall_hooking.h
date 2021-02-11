#ifndef LKM_TLSKIT_SYSCALL_HOOKING_H
#define LKM_TLSKIT_SYSCALL_HOOKING_H

/**
 * Data type for syscalls
 */
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

/**
 * Enable syscall hooking
 * @return 0 on success, -1 on error
 */
int enable_syscall_hooking(void);

/**
 * Disable syscall hooking
 */
void disable_syscall_hooking(void);

/**
 * Add a system call hook
 * @param nr
 * @param hook_addr
 * @return 0 on success, -1 else
 */
int add_syscall_hook(unsigned long nr, unsigned long *hook_addr);

/**
 * Remove a system call hook
 * @param nr
 * @return 0 on success, -1 else
 */
int rm_syscall_hook(unsigned long nr);

/**
 * Get the original sys_call ptr
 * @param nr
 * @return address of the syscall, 0 on failure
 */
unsigned long get_original_syscall(unsigned long nr);

#endif //LKM_TLSKIT_SYSCALL_HOOKING_H
