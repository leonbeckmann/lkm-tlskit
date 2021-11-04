#include "helper.h"
#include <linux/uaccess.h>
#include <crypto/hash.h>

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

// from https://gist.github.com/vkobel/3100cea3625ca765e4153782314bd03d
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

int sha256(const unsigned char *src, size_t len, unsigned char *dst) {

    struct crypto_shash *alg;
    int ret;
    struct sdesc *sdesc;

    alg = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(alg)) {
        return -1;
    }

    if (NULL == (sdesc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(alg), GFP_KERNEL))) {
        crypto_free_shash(alg);
        return -1;
    }

    sdesc->shash.tfm = alg;

    // calculate hash
    if (0 > crypto_shash_digest(&sdesc->shash, src, len, dst)) {
        ret = -1;
        goto out;
    }

    ret = 0;

out:
    kfree(sdesc);
    crypto_free_shash(alg);
    return ret;
}