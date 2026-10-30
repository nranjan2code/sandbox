/* Own the process group outside the jail. Target code cannot signal either
 * supervisor, inherits no control descriptors, and cannot leave the group:
 * the Seatbelt profile rejects setsid, setpgid and posix_spawn (including its
 * in-kernel group/session attributes). Do not remove one half of this contract.
 */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#if SYS_syscall != 0 || SYS_setpgid != 82 || SYS_setsid != 147 || SYS_posix_spawn != 244
#error Darwin syscall table changed; review the Seatbelt detachment gates
#endif
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static void die(const char *reason) { perror(reason); _exit(126); }
static void group_exit(void) { kill(-getpgrp(), SIGKILL); _exit(126); }
static void close_on_exec(int fd) {
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) die("control descriptor");
}
static int connect_worker_input(const char *path) {
    if (path == NULL) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(address.sun_path)) { errno = ENAMETOOLONG; return -1; }
    memcpy(address.sun_path, path, length + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    char ready = 0;
    if (read(fd, &ready, 1) != 1 || ready != 'R') {
        close(fd);
        errno = EPROTO;
        return -1;
    }
    return fd;
}

/* Hold the anchor PID until the kernel reports every member dead. This avoids
 * PID/group reuse and does not mistake a delivered signal for completed work.
 * Zombies cannot execute or mutate files and are reaped by their owners.
 */
static int group_dead(pid_t group) {
    errno = 0;
    int count = proc_listpids(PROC_PGRP_ONLY, (uint32_t)group, NULL, 0);
    if ((count == 0 && errno != 0) || count < 0 || count > 4 * 1024 * 1024) return 0;
    size_t capacity = (size_t)count + 64 * sizeof(pid_t);
    pid_t *pids = calloc(1, capacity);
    if (!pids) return 0;
    errno = 0;
    int bytes = proc_listpids(PROC_PGRP_ONLY, (uint32_t)group, pids, (int)capacity);
    if ((bytes == 0 && errno != 0) || bytes < 0 || (size_t)bytes >= capacity) { free(pids); return 0; }
    int dead = 1;
    for (int i = 0; i < bytes / (int)sizeof(pid_t); ++i) {
        if (pids[i] <= 0) continue;
        struct proc_bsdinfo info;
        errno = 0;
        int n = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (n == (int)sizeof(info)) {
            if (info.pbi_status != SZOMB) { dead = 0; break; }
        } else if (errno != ESRCH) { dead = 0; break; }
    }
    free(pids);
    return dead;
}

static int complete(int receipt, int code) {
    if (lseek(receipt, 0, SEEK_SET) < 0 ||
        dprintf(receipt, "{\"cleanup_verified\":true,\"exit_code\":%d}", code) < 0 ||
        ftruncate(receipt, lseek(receipt, 0, SEEK_CUR)) || fsync(receipt) || close(receipt)) return 126;
    return 0;
}

int main(int argc, char **argv) {
    int receipt = -1;
    char *worker_input_socket = NULL;
    while (argc > 3) {
        if (!strcmp(argv[1], "--lease-lock")) {
            int lease = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (lease < 0 || flock(lease, LOCK_SH | LOCK_NB)) die("execution lease");
        } else if (!strcmp(argv[1], "--receipt")) {
            receipt = open(argv[2], O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            if (receipt < 0) die("completion receipt");
        } else if (!strcmp(argv[1], "--worker-input-socket")) {
            worker_input_socket = argv[2];
        } else { break; }
        argv += 2; argc -= 2;
    }
    if (receipt < 0) return 126;
    if (argc < 5) return 126; /* -p profile -- executable [args] */
    int worker_input = connect_worker_input(worker_input_socket);
    if (worker_input_socket != NULL && worker_input < 0) die("private worker input");
    struct pollfd owner = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
    if (poll(&owner, 1, 0) != 0) return complete(receipt, 143); /* never start work for a dead owner */
    int result[2], life[2];
    if (pipe(result) || pipe(life)) die("control pipe");
    for (int i = 0; i < 2; ++i) { close_on_exec(result[i]); close_on_exec(life[i]); }
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) die("signal handler");
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || signal(SIGCHLD, SIG_DFL) == SIG_ERR) die("signal disposition");
    pid_t anchor = fork();
    if (anchor < 0) die("anchor fork");
    if (anchor == 0) {
        close(result[0]); close(life[1]);
        /* One owner establishes the group. Do not race a second setpgid in
         * the child against parent setup/teardown. No target exists before
         * the parent's handoff, and EOF cannot kill an unrelated old group. */
        char admitted = 0;
        ssize_t count;
        do { count = read(life[0], &admitted, 1); } while (count < 0 && errno == EINTR);
        if (count != 1 || admitted != 'G') _exit(126);
        if (getpgrp() != getpid()) { errno = EPERM; die("anchor group identity"); }
        pid_t target = fork();
        if (target < 0) group_exit();
        if (target == 0) {
            close(result[1]); close(life[0]);
            if (worker_input >= 0) {
                if ((worker_input != 3 && dup2(worker_input, 3) < 0) ||
                    fcntl(3, F_SETFD, 0) < 0) die("target private I/O");
                if (worker_input != 3) close(worker_input);
            }
            int input = open("/dev/null", O_RDONLY);
            if (input < 0 || dup2(input, STDIN_FILENO) < 0) die("target input");
            if (input != STDIN_FILENO) close(input);
            execv("/usr/bin/sandbox-exec", argv);
            die("sandbox-exec");
        }
        if (worker_input >= 0) close(worker_input);
        /* No output descriptors may keep a completed target's streams open. */
        close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
        int reported = 0;
        for (;;) {
            int status;
            pid_t reaped = reported ? 0 : waitpid(target, &status, WNOHANG);
            if (reaped == target) {
                if (write(result[1], &status, sizeof(status)) != sizeof(status)) group_exit();
                reported = 1;
            } else if (reaped < 0 && errno != EINTR) { group_exit(); }
            struct pollfd fd = {.fd = life[0], .events = POLLIN | POLLHUP};
            int ready = poll(&fd, 1, 10);
            /* The anchor tears down the group even if its supervisor is killed. */
            if ((ready > 0 && fd.revents) || (ready < 0 && errno != EINTR)) group_exit();
        }
    }
    if (worker_input >= 0) close(worker_input);
    close(result[1]); close(life[0]);
    /* The anchor is waiting on the private lifeline and cannot fork a target. */
    if (setpgid(anchor, anchor) || write(life[1], "G", 1) != 1) {
        close(life[1]); kill(anchor, SIGKILL); waitpid(anchor, NULL, 0); return 126;
    }
    int status = 0, completed = 0;
    struct pollfd fds[2] = {{.fd = result[0], .events = POLLIN | POLLHUP},
                            {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP}};
    while (!stopping) {
        int ready = poll(fds, 2, -1);
        if (ready < 0) { if (errno == EINTR) continue; break; }
        if (fds[1].revents) break; /* owner closed its private lifetime pipe */
        if (fds[0].revents) {
            completed = read(result[0], &status, sizeof(status)) == sizeof(status);
            break;
        }
    }
    kill(-anchor, SIGSTOP);
    kill(-anchor, SIGKILL);
    int dead = 0;
    for (int i = 0; i < 500; ++i) {
        if (group_dead(anchor)) { dead = 1; break; }
        usleep(10000);
    }
    close(life[1]); close(result[0]);
    while (waitpid(anchor, NULL, 0) < 0 && errno == EINTR) {}
    if (!dead) { fprintf(stderr, "Sandbox descendant cleanup could not be verified\n"); return 126; }
    int code = !completed ? 143 : WIFEXITED(status) ? WEXITSTATUS(status) :
        WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 126;
    return complete(receipt, code);
}
