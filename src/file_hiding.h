#ifndef LKM_TLSKIT_FILE_HIDING_H
#define LKM_TLSKIT_FILE_HIDING_H

/**
 * Enable file hiding
 * @return 0 on success, -1 on error
 */
void enable_file_hiding(void);

/**
 * Disable file hiding
 */
void disable_file_hiding(void);

#endif //LKM_TLSKIT_FILE_HIDING_H
