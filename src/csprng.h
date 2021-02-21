#ifndef LKM_TLSKIT_CSPRNG_H
#define LKM_TLSKIT_CSPRNG_H

/**
 * Replace CSPRNG by predictable PRNG
 * @return 0 on success, -1 else
 */
int enable_csprng_hook(void);

/**
 * disable the crypto secure PRNG hook
 */
void disable_csprng_hook(void);

#endif //LKM_TLSKIT_CSPRNG_H
