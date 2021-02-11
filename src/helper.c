#include "helper.h"
#include <linux/uaccess.h>

void unprotect_paging_mode(void) {

    /*
     * Manipulate the WP (write protection) bit in the cr0 control register in the CPU
     * WP bit is 16. bit in CR0
     *
     * Clear WP
     * Attention:
     * This could be disabled in Linux 5.* kernels, since further integrity checks will check if WP has been modified
     */

    write_cr0(read_cr0() & (~0x10000));
}

void protect_paging_mode(void) {
    write_cr0(read_cr0() | 0x10000);
}