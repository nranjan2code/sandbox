#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int type = 0;
    socklen_t length = sizeof(type);
    int interactive = argc == 1;
    int result = getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &length);
    if (interactive) {
        if (result != 0 || type != SOCK_STREAM) return 10;
    } else if (strcmp(argv[1], "ordinary") || result != -1 || errno != EPERM) return 11;
    if (getsockopt(2, SOL_SOCKET, SO_TYPE, &type, &length) != -1 || errno != EPERM) return 12;
    if (getsockopt(3, SOL_SOCKET, SO_ERROR, &type, &length) != -1 || errno != EPERM) return 13;
    if (setsockopt(3, SOL_SOCKET, SO_RCVBUF, &type, sizeof(type)) != -1 || errno != EPERM) return 14;
    if (socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM) return 15;
    if (socket(AF_UNIX, SOCK_STREAM, 0) != -1 || errno != EPERM) return 16;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != -1 || errno != EPERM) return 17;
    struct sockaddr address = {0};
    if (connect(3, &address, sizeof(address)) != -1 || errno != EPERM) return 18;
    struct msghdr message = {0};
    if (sendmsg(3, &message, 0) != -1 || errno != EPERM) return 19;
    if (recvmsg(3, &message, 0) != -1 || errno != EPERM) return 20;
    if (!interactive) { puts("ordinary-denied"); return 0; }
    char input[8] = {0};
    if (read(3, input, 7) != 7 || memcmp(input, "request", 7)) return 21;
    if (write(3, "private-channel-ok\n", 19) != 19) return 22;
    return 0;
}
