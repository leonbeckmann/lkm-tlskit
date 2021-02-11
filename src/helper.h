#ifndef LKM_TLSKIT_HELPER_H
#define LKM_TLSKIT_HELPER_H

/**
 * Enable page writing for read-only pages
 */
void unprotect_paging_mode(void);

/**
 * Disable page writing for read-only pages
 */
void protect_paging_mode(void);

#endif //LKM_TLSKIT_HELPER_H
