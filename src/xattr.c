#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include "shared.h"

void print_usage(void) {
    printf("Usage:\n"
           "\tHide: ./xattr hide <path> ...\n"
           "\tHide: ./xattr unhide <path> ...\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[-] xattr: missing arguments\n");
        print_usage();
        return -1;
    }

    if (!strcmp(argv[1], "hide")) {
        // hide all given paths
        for (int i = 2; i < argc; i++) {
            if (0 > setxattr(argv[i], HIDDEN_XATTR, NULL, 0, 0)) {
                printf("[-] xattr: Cannot set attribute '%s' for path '%s'\n", HIDDEN_XATTR, argv[i]);
            }
        }
    } else if (!strcmp(argv[1], "unhide")) {
        // unhide all given paths
        for (int i = 2; i < argc; i++) {
            if (0 > removexattr(argv[i], HIDDEN_XATTR)) {
                printf("[-] xattr: Cannot remove attribute '%s' for path '%s'\n", HIDDEN_XATTR, argv[i]);
            }
        }
    } else {
        printf("[-] xattr: invalid command\n");
        print_usage();
        return -1;
    }

    printf("[+] xattr: Done\n");
    return 0;
}

