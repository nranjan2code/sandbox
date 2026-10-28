#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "detach")) {
        if (setsid() != -1 || errno != EPERM) return 10;
        if (setpgid(0, 0) != -1 || errno != EPERM) return 11;
        posix_spawnattr_t attr;
        if (posix_spawnattr_init(&attr) || posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP) ||
            posix_spawnattr_setpgroup(&attr, 0)) return 12;
        char *args[] = {"sleep", "0", NULL}; pid_t child;
        int error = posix_spawn(&child, "/bin/sleep", NULL, &attr, args, environ);
        posix_spawnattr_destroy(&attr);
        if (error == 0) { waitpid(child, NULL, 0); return 13; }
        errno = 0;
        /* Exercise the deprecated indirect ABI deliberately; normal application
         * code must not use it, but it must not bypass the detachment gates. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        int indirect = syscall(SYS_syscall, SYS_setsid);
#pragma clang diagnostic pop
        if (indirect != -1 || (errno != EPERM && errno != ENOSYS)) return 18;
        puts("detachment denied"); return 0;
    }
    if (!strcmp(argv[1], "descendant") || !strcmp(argv[1], "owner")) {
        pid_t child = fork(); if (child < 0) return 14;
        if (child > 0) {
            if (!strcmp(argv[1], "owner")) {
                int ready = open("owner-ready", O_CREAT | O_WRONLY, 0600);
                if (ready < 0) return 19;
                close(ready); sleep(4);
            }
            return 0;
        }
        close(1); close(2); sleep(1);
        int fd = open("late-marker", O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) { write(fd, "survived", 8); close(fd); }
        return 0;
    }
    if (!strcmp(argv[1], "hold")) { close(1); close(2); sleep(5); return 0; }
    if (!strcmp(argv[1], "fork")) {
        pid_t child = fork(); if (child < 0) return 15;
        if (child == 0) { execl("/bin/echo", "echo", "fork-exec-ok", NULL); return 16; }
        int status; waitpid(child, &status, 0); return WIFEXITED(status) ? WEXITSTATUS(status) : 17;
    }
    return 3;
}
