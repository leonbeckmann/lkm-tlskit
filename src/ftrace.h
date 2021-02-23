#ifndef LKM_TLSKIT_FTRACE_H
#define LKM_TLSKIT_FTRACE_H

#include <linux/ftrace.h>

/**
 * Ftrace stuff
 * from https://github.com/ilammy/ftrace-hook/
 */

/*
 * detect recursion using function ret addr ro prevent vicious recursive loops when hooking
 */
#pragma GCC optimize("-fno-optimize-sibling-calls")

struct ftrace_hook {
    const char *name;       // function name
    void *function;         // ptr to hook
    void *original;         // ptr to location that points to orig

    unsigned long address;  // kernel address of function entry
    struct ftrace_ops ops;  // ftrace options
};

/**
 * Enable ftrace hooks
 * @param hooks
 * @param count
 * @return 0 on success, negative value else
 */
int ftrace_install_hooks(struct ftrace_hook *hooks, size_t count);

/**
 * Disable ftrace hooks
 * @param hooks
 * @param count
 */
void ftrace_remove_hooks(struct ftrace_hook *hooks, size_t count);

#endif //LKM_TLSKIT_FTRACE_H
