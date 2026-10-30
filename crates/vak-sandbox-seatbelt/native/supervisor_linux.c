#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define MAX_RULES 256
#define CLEANUP_MILLISECONDS 1000

static volatile sig_atomic_t stopping = 0;

static int add_path_rule(int ruleset, const char *path, uint64_t access);

static int connect_worker_input(const char *path) {
    if (path == NULL) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(address.sun_path, path, length + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
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

static void stop_handler(int signal_number) {
    stopping = signal_number;
}

static int fail(const char *message) {
    (void)fprintf(stderr, "Linux supervisor: %s: %s\n", message, strerror(errno));
    return 126;
}

static int install_landlock(char **reads, size_t read_count, char **writes,
                            size_t write_count) {
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 5) {
        errno = abi < 0 ? errno : EOPNOTSUPP;
        return -1;
    }

    uint64_t read_access = LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t write_access = LANDLOCK_ACCESS_FS_WRITE_FILE |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_MAKE_CHAR |
                            LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_MAKE_REG |
                            LANDLOCK_ACCESS_FS_MAKE_SOCK |
                            LANDLOCK_ACCESS_FS_MAKE_FIFO |
                            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                            LANDLOCK_ACCESS_FS_MAKE_SYM |
                            LANDLOCK_ACCESS_FS_REFER |
                            LANDLOCK_ACCESS_FS_TRUNCATE;
    uint64_t handled = read_access | write_access | LANDLOCK_ACCESS_FS_IOCTL_DEV;
    struct landlock_ruleset_attr ruleset_attr = {.handled_access_fs = handled};
    int ruleset = (int)syscall(SYS_landlock_create_ruleset, &ruleset_attr,
                               sizeof(ruleset_attr), 0);
    if (ruleset < 0) {
        return -1;
    }

    size_t rule_count = read_count + write_count + 3;
    if (rule_count > MAX_RULES) {
        (void)close(ruleset);
        errno = E2BIG;
        return -1;
    }
    for (size_t index = 0; index < read_count; index++) {
        if (add_path_rule(ruleset, reads[index], read_access) != 0) {
            (void)fprintf(stderr, "Linux supervisor: could not add a read rule: %s\n",
                          strerror(errno));
            (void)close(ruleset);
            return -1;
        }
    }
    for (size_t index = 0; index < write_count; index++) {
        if (add_path_rule(ruleset, writes[index], read_access | write_access) != 0) {
            (void)fprintf(stderr, "Linux supervisor: could not add a write rule: %s\n",
                          strerror(errno));
            (void)close(ruleset);
            return -1;
        }
    }
    const char *devices[] = {"/dev/null", "/dev/random", "/dev/urandom"};
    for (size_t index = 0; index < sizeof(devices) / sizeof(devices[0]); index++) {
        if (add_path_rule(ruleset, devices[index], read_access | write_access) != 0) {
            (void)fprintf(stderr, "Linux supervisor: could not add a device rule: %s\n",
                          strerror(errno));
            (void)close(ruleset);
            return -1;
        }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
        (void)close(ruleset);
        return -1;
    }
    (void)close(ruleset);
    return 0;
}

static int add_path_rule(int ruleset, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    struct stat metadata;
    if (fstat(fd, &metadata) != 0) {
        (void)close(fd);
        return -1;
    }
    if (!S_ISDIR(metadata.st_mode)) {
        access &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                  LANDLOCK_ACCESS_FS_WRITE_FILE;
        if (S_ISREG(metadata.st_mode)) {
            access |= (access & LANDLOCK_ACCESS_FS_WRITE_FILE) != 0
                          ? LANDLOCK_ACCESS_FS_TRUNCATE
                          : 0;
        }
    }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int result = (int)syscall(SYS_landlock_add_rule, ruleset,
                              LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return result;
}

#if defined(__x86_64__)
#define TARGET_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define TARGET_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "Linux supervisor supports only x86_64 and aarch64"
#endif

#define DENY_SYSCALL(number, error) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error))

static int install_signal_guard(pid_t target_group) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TARGET_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
#ifdef __NR_kill
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(-target_group), 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
#endif
#ifdef __NR_tkill
        DENY_SYSCALL(__NR_tkill, EPERM),
#endif
#ifdef __NR_tgkill
        DENY_SYSCALL(__NR_tgkill, EPERM),
#endif
#ifdef __NR_rt_sigqueueinfo
        DENY_SYSCALL(__NR_rt_sigqueueinfo, EPERM),
#endif
#ifdef __NR_rt_tgsigqueueinfo
        DENY_SYSCALL(__NR_rt_tgsigqueueinfo, EPERM),
#endif
#ifdef __NR_pidfd_send_signal
        DENY_SYSCALL(__NR_pidfd_send_signal, EPERM),
#endif
#ifdef __NR_pidfd_open
        DENY_SYSCALL(__NR_pidfd_open, EPERM),
#endif
#ifdef __NR_pidfd_getfd
        DENY_SYSCALL(__NR_pidfd_getfd, EPERM),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        return -1;
    }
    return 0;
}

static int install_seccomp(int interactive) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TARGET_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
#ifdef __NR_socket
        DENY_SYSCALL(__NR_socket, EPERM),
#endif
#ifdef __NR_socketpair
        DENY_SYSCALL(__NR_socketpair, EPERM),
#endif
#ifdef __NR_connect
        DENY_SYSCALL(__NR_connect, EPERM),
#endif
#ifdef __NR_bind
        DENY_SYSCALL(__NR_bind, EPERM),
#endif
#ifdef __NR_listen
        DENY_SYSCALL(__NR_listen, EPERM),
#endif
#ifdef __NR_accept
        DENY_SYSCALL(__NR_accept, EPERM),
#endif
#ifdef __NR_accept4
        DENY_SYSCALL(__NR_accept4, EPERM),
#endif
#ifdef __NR_sendto
        DENY_SYSCALL(__NR_sendto, EPERM),
#endif
#ifdef __NR_sendmsg
        DENY_SYSCALL(__NR_sendmsg, EPERM),
#endif
#ifdef __NR_recvfrom
        DENY_SYSCALL(__NR_recvfrom, EPERM),
#endif
#ifdef __NR_recvmsg
        DENY_SYSCALL(__NR_recvmsg, EPERM),
#endif
#ifdef __NR_shutdown
        DENY_SYSCALL(__NR_shutdown, EPERM),
#endif
#ifdef __NR_setsockopt
        DENY_SYSCALL(__NR_setsockopt, EPERM),
#endif
#ifdef __NR_getsockopt
        /* Runtime stream wrappers inspect the inherited private channel. Only
         * its socket type is readable; this adds no socket creation or egress. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 8),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOL_SOCKET, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_TYPE, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, interactive ? SECCOMP_RET_ALLOW : (SECCOMP_RET_ERRNO | EPERM)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
#endif
#ifdef __NR_setsid
        DENY_SYSCALL(__NR_setsid, EPERM),
#endif
#ifdef __NR_setpgid
        DENY_SYSCALL(__NR_setpgid, EPERM),
#endif
#ifdef __NR_unshare
        DENY_SYSCALL(__NR_unshare, EPERM),
#endif
#ifdef __NR_setns
        DENY_SYSCALL(__NR_setns, EPERM),
#endif
#ifdef __NR_clone
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                 CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
                     CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME,
                 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
#endif
#ifdef __NR_clone3
        DENY_SYSCALL(__NR_clone3, ENOSYS),
#endif
#ifdef __NR_io_uring_setup
        DENY_SYSCALL(__NR_io_uring_setup, EPERM),
#endif
#ifdef __NR_ptrace
        DENY_SYSCALL(__NR_ptrace, EPERM),
#endif
#ifdef __NR_mount
        DENY_SYSCALL(__NR_mount, EPERM),
#endif
#ifdef __NR_umount2
        DENY_SYSCALL(__NR_umount2, EPERM),
#endif
#ifdef __NR_pivot_root
        DENY_SYSCALL(__NR_pivot_root, EPERM),
#endif
#ifdef __NR_chroot
        DENY_SYSCALL(__NR_chroot, EPERM),
#endif
#ifdef __NR_open_tree
        DENY_SYSCALL(__NR_open_tree, EPERM),
#endif
#ifdef __NR_move_mount
        DENY_SYSCALL(__NR_move_mount, EPERM),
#endif
#ifdef __NR_fsopen
        DENY_SYSCALL(__NR_fsopen, EPERM),
#endif
#ifdef __NR_fsconfig
        DENY_SYSCALL(__NR_fsconfig, EPERM),
#endif
#ifdef __NR_fsmount
        DENY_SYSCALL(__NR_fsmount, EPERM),
#endif
#ifdef __NR_mount_setattr
        DENY_SYSCALL(__NR_mount_setattr, EPERM),
#endif
#ifdef __NR_open_by_handle_at
        DENY_SYSCALL(__NR_open_by_handle_at, EPERM),
#endif
#ifdef __NR_name_to_handle_at
        DENY_SYSCALL(__NR_name_to_handle_at, EPERM),
#endif
#ifdef __NR_capset
        DENY_SYSCALL(__NR_capset, EPERM),
#endif
#ifdef __NR_keyctl
        DENY_SYSCALL(__NR_keyctl, EPERM),
#endif
#ifdef __NR_add_key
        DENY_SYSCALL(__NR_add_key, EPERM),
#endif
#ifdef __NR_request_key
        DENY_SYSCALL(__NR_request_key, EPERM),
#endif
#ifdef __NR_bpf
        DENY_SYSCALL(__NR_bpf, EPERM),
#endif
#ifdef __NR_userfaultfd
        DENY_SYSCALL(__NR_userfaultfd, EPERM),
#endif
#ifdef __NR_kcmp
        DENY_SYSCALL(__NR_kcmp, EPERM),
#endif
#ifdef __NR_process_madvise
        DENY_SYSCALL(__NR_process_madvise, EPERM),
#endif
#ifdef __NR_process_mrelease
        DENY_SYSCALL(__NR_process_mrelease, EPERM),
#endif
#ifdef __NR_process_vm_readv
        DENY_SYSCALL(__NR_process_vm_readv, EPERM),
#endif
#ifdef __NR_process_vm_writev
        DENY_SYSCALL(__NR_process_vm_writev, EPERM),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        return -1;
    }
    return 0;
}

static bool group_exists(pid_t group) {
    if (kill(-group, 0) == 0) {
        return true;
    }
    return errno == EPERM;
}

static int probe(void) {
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                          LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 5) {
        return 1;
    }
    uint32_t action = SECCOMP_RET_ERRNO;
    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) != 0) {
        return 1;
    }
    return 0;
}

static void reap_group(void) {
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0) {
    }
}

static bool stop_group(pid_t group) {
    (void)kill(-group, SIGTERM);
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    for (int index = 0; index < CLEANUP_MILLISECONDS / 10; index++) {
        reap_group();
        if (!group_exists(group)) {
            return true;
        }
        (void)nanosleep(&pause, NULL);
    }
    (void)kill(-group, SIGKILL);
    for (int index = 0; index < CLEANUP_MILLISECONDS / 10; index++) {
        reap_group();
        if (!group_exists(group)) {
            return true;
        }
        (void)nanosleep(&pause, NULL);
    }
    reap_group();
    return !group_exists(group);
}

static int write_receipt(const char *path, bool cleanup_verified, int exit_code) {
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat metadata;
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0077) != 0) {
        (void)close(fd);
        errno = EPERM;
        return -1;
    }
    char value[96];
    int length = snprintf(value, sizeof(value),
                          "{\"cleanup_verified\":%s,\"exit_code\":%d}",
                          cleanup_verified ? "true" : "false", exit_code);
    if (length <= 0 || (size_t)length >= sizeof(value) ||
        write(fd, value, (size_t)length) != (ssize_t)length || fsync(fd) != 0) {
        (void)close(fd);
        return -1;
    }
    return close(fd);
}

static void reset_child_signals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGHUP, &action, NULL);
    sigset_t empty;
    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
}

static int drop_child_privileges(void) {
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(SYS_capset, &header, capabilities) != 0) {
        return -1;
    }
#ifdef PR_CAP_AMBIENT
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        return -1;
    }
#endif
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        return probe();
    }
    char *cwd = NULL;
    char *receipt = NULL;
    char *lease_lock = NULL;
    char *worker_input_socket = NULL;
    char *reads[MAX_RULES];
    char *writes[MAX_RULES];
    size_t read_count = 0;
    size_t write_count = 0;
    int index = 1;
    while (index < argc && strcmp(argv[index], "--") != 0) {
        if (index + 1 >= argc) {
            errno = EINVAL;
            return fail("invalid arguments");
        }
        if (strcmp(argv[index], "--cwd") == 0) {
            cwd = argv[index + 1];
        } else if (strcmp(argv[index], "--receipt") == 0) {
            receipt = argv[index + 1];
        } else if (strcmp(argv[index], "--lease-lock") == 0) {
            lease_lock = argv[index + 1];
        } else if (strcmp(argv[index], "--worker-input-socket") == 0) {
            worker_input_socket = argv[index + 1];
        } else if (strcmp(argv[index], "--read") == 0 && read_count < MAX_RULES) {
            reads[read_count++] = argv[index + 1];
        } else if (strcmp(argv[index], "--write") == 0 && write_count < MAX_RULES) {
            writes[write_count++] = argv[index + 1];
        } else {
            errno = EINVAL;
            return fail("unsupported policy argument");
        }
        index += 2;
    }
    if (index + 1 >= argc || cwd == NULL || receipt == NULL) {
        errno = EINVAL;
        return fail("missing command or policy");
    }
    char **command = &argv[index + 1];
    int lease_fd = -1;
    if (lease_lock != NULL) {
        lease_fd = open(lease_lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (lease_fd < 0 || flock(lease_fd, LOCK_SH) != 0) {
            if (lease_fd >= 0) {
                (void)close(lease_fd);
            }
            return fail("could not acquire Realm execution gate");
        }
    }
    int worker_input = connect_worker_input(worker_input_socket);
    if (worker_input_socket != NULL && worker_input < 0) {
        return fail("could not connect private worker input");
    }

    pid_t owner = getppid();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        return fail("could not install stop handlers");
    }
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        return fail("could not establish supervisor lifetime");
    }
    if (getppid() != owner) {
        stopping = SIGTERM;
    }

    pid_t child = fork();
    if (child < 0) {
        return fail("could not start restricted command");
    }
    if (child == 0) {
        reset_child_signals();
        if (worker_input >= 0) {
            if ((worker_input != 3 && dup2(worker_input, 3) < 0) ||
                fcntl(3, F_SETFD, 0) < 0) _exit(126);
            if (worker_input != 3) (void)close(worker_input);
        }
        int null_input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_input < 0 || dup2(null_input, STDIN_FILENO) < 0) {
            _exit(126);
        }
        if (null_input != STDIN_FILENO) {
            (void)close(null_input);
        }
        if (drop_child_privileges() != 0 || setpgid(0, 0) != 0 || chdir(cwd) != 0 ||
            install_landlock(reads, read_count, writes, write_count) != 0 ||
            install_signal_guard(getpid()) != 0 || install_seccomp(worker_input >= 0) != 0) {
            (void)fprintf(stderr, "Linux supervisor: restriction setup failed: %s\n",
                          strerror(errno));
            _exit(126);
        }
        execvp(command[0], command);
        (void)fprintf(stderr, "Linux supervisor: could not execute command: %s\n",
                      strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (worker_input >= 0) (void)close(worker_input);
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
        int saved_errno = errno;
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        errno = saved_errno;
        return fail("could not establish restricted process group");
    }

    int child_status = 0;
    bool child_reaped = false;
    while (!child_reaped && stopping == 0) {
        pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            stopping = SIGTERM;
            break;
        }
        struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
        int ready = poll(&input, 1, 10);
        if (ready > 0 && (input.revents & (POLLIN | POLLHUP)) != 0) {
            char byte;
            ssize_t count = read(STDIN_FILENO, &byte, 1);
            if (count <= 0 || byte != 0) {
                stopping = SIGTERM;
            }
        }
    }

    bool cleanup_verified = stop_group(child);
    int exit_code = 143;
    if (child_reaped) {
        exit_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status)
                                            : 128 + WTERMSIG(child_status);
    } else if (stopping == SIGINT) {
        exit_code = 130;
    }
    if (write_receipt(receipt, cleanup_verified, exit_code) != 0) {
        return fail("could not write cleanup receipt");
    }
    if (lease_fd >= 0) {
        (void)close(lease_fd);
    }
    return cleanup_verified ? 0 : 126;
}
