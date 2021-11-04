#ifndef LKM_TLSKIT_HELPER_H
#define LKM_TLSKIT_HELPER_H

#include <linux/types.h>

/**
 * Enable page writing for read-only pages
 */
void unprotect_paging_mode(void);

/**
 * Disable page writing for read-only pages
 */
void protect_paging_mode(void);

/**
 * Create a sha256 hash
 * @param src
 * @param len
 * @param dst
 * @return 0 on success, -1 else
 */
int sha256(const unsigned char *src, size_t len, unsigned char *dst);

#endif //LKM_TLSKIT_HELPER_H
