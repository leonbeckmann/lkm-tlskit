#include "lkm.h"

#include <linux/module.h>

static int __init tlskit_init(void) {
    printk("Insert rootkit\n");
    return 0;
}

static void __exit tlskit_exit(void) {
    printk("Remove rootkit\n");
}

module_init(tlskit_init);
module_exit(tlskit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leon Beckmann");