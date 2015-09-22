#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <linux/limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <sys/reg.h>
#include <sys/wait.h>

#include <seccomp.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#define SYSCALL_NAME_MAX 30

static void check(int rc) {
    if (rc < 0) errx(EXIT_FAILURE, "%s", strerror(-rc));
}

__attribute__((format(printf, 2, 3))) static void check_posix(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
}

__attribute__((format(printf, 2, 3))) static bool check_eagain(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1 && errno != EAGAIN) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
    return rc == -1 && errno == EAGAIN;
}

static char *join_path(const char *left, const char *right) {
    char *dst;
    check_posix(asprintf(&dst, "%s/%s", left, right), "asprintf");
    return dst;
}

static void mountx(const char *source, const char *target, const char *filesystemtype,
                   unsigned long mountflags, const void *data) {
    check_posix(mount(source, target, filesystemtype, mountflags, data),
                "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

struct bind_list {
    struct bind_list *next;
    bool read_only;
    char arg[];
};

static struct bind_list *bind_list_alloc(const char *arg, bool read_only) {
    size_t len = strlen(arg);
    struct bind_list *next = malloc(sizeof(struct bind_list) + len + 1);
    if (!next) err(EXIT_FAILURE, "malloc");

    next->next = NULL;
    next->read_only = read_only;
    strcpy(next->arg, arg);
    return next;
}

static void bind_list_apply(const char *root, struct bind_list *list) {
    for (; list; list = list->next) {
        char *dst = join_path(root, list->arg);
        // Only use MS_REC with writable mounts to work around a kernel bug:
        // https://bugzilla.kernel.org/show_bug.cgi?id=24912
        mountx(list->arg, dst, "bind", MS_BIND | (list->read_only ? 0 : MS_REC), NULL);
        if (list->read_only)
            mountx(list->arg, dst, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        free(dst);
    }
}

static void bind_list_free(struct bind_list *list) {
    while (list) {
        struct bind_list *next = list->next;
        free(list);
        list = next;
    }
}

static const char *const systemd_bus_name = "org.freedesktop.systemd1";
static const char *const systemd_path_name = "/org/freedesktop/systemd1";
static const char *const manager_interface = "org.freedesktop.systemd1.Manager";

static void wait_for_unit(pid_t child_pid, const char *expected_name) {
    for (;;) {
        char *unit;
        check(sd_pid_get_unit(child_pid, &unit));
        bool equal = !strcmp(expected_name, unit);
        free(unit);
        if (equal) break;
    }
}

static void start_scope_unit(sd_bus *connection, pid_t child_pid, long memory_limit,
                             char *devices, const char *unit_name) {
    sd_bus_message *message = NULL;
    check(sd_bus_message_new_method_call(connection, &message, systemd_bus_name, systemd_path_name,
                                         manager_interface, "StartTransientUnit"));

    check(sd_bus_message_append(message, "ss", unit_name, "fail"));
    check(sd_bus_message_open_container(message, 'a', "(sv)"));
    check(sd_bus_message_append(message, "(sv)", "PIDs", "au", 1, child_pid));
    check(sd_bus_message_append(message, "(sv)", "Description", "s",
                                "Playpen application sandbox"));
    check(sd_bus_message_append(message, "(sv)", "MemoryLimit", "t",
                                1024ULL * 1024ULL * (unsigned long long)memory_limit));
    check(sd_bus_message_append(message, "(sv)", "DevicePolicy", "s", "strict"));

    if (devices) {
        check(sd_bus_message_open_container(message, 'r', "sv"));
        check(sd_bus_message_append(message, "s", "DeviceAllow"));
        check(sd_bus_message_open_container(message, 'v', "a(ss)"));
        check(sd_bus_message_open_container(message, 'a', "(ss)"));

        for (char *s_ptr = devices, *saveptr; ; s_ptr = NULL) {
            const char *device = strtok_r(s_ptr, ",", &saveptr);
            if (!device) break;
            char *split = strchr(device, ':');
            if (!split) errx(EXIT_FAILURE, "invalid device parameter `%s`", device);
            *split = '\0';
            sd_bus_message_append(message, "(ss)", device, split + 1);
        }

        check(sd_bus_message_close_container(message));
        check(sd_bus_message_close_container(message));
        check(sd_bus_message_close_container(message));
    }

    check(sd_bus_message_append(message, "(sv)", "CPUAccounting", "b", 1));
    check(sd_bus_message_append(message, "(sv)", "BlockIOAccounting", "b", 1));
    check(sd_bus_message_close_container(message));
    check(sd_bus_message_append(message, "a(sa(sv))", 0));

    sd_bus_error error = SD_BUS_ERROR_NULL;
    int rc = sd_bus_call(connection, message, 0, &error, NULL);
    if (rc < 0) errx(EXIT_FAILURE, "%s",
                     sd_bus_error_is_set(&error) ? error.message : strerror(-rc));
    sd_bus_message_unref(message);

    wait_for_unit(child_pid, unit_name);
}

static void stop_scope_unit(sd_bus *connection, const char *unit_name) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int rc = sd_bus_call_method(connection, systemd_bus_name, systemd_path_name, manager_interface,
                                "StopUnit", &error, NULL, "ss", unit_name, "fail");
    if (rc < 0) {
        if (sd_bus_error_is_set(&error)) {
            // NoSuchUnit errors are expected as the contained processes can die at any point.
            if (strcmp(error.name, "org.freedesktop.systemd1.NoSuchUnit"))
                errx(EXIT_FAILURE, "%s", error.message);
            sd_bus_error_free(&error);
        } else
            errx(EXIT_FAILURE, "%s", strerror(-rc));
    }
}

static void epoll_add(int epoll_fd, int fd, uint32_t events) {
    struct epoll_event event = { .data.fd = fd, .events = events };
    check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event), "epoll_ctl");
}

static void copy_to_stdstream(int in_fd, int out_fd) {
    uint8_t buffer[BUFSIZ];
    ssize_t n = read(in_fd, buffer, sizeof(buffer));
    if (check_eagain(n, "read")) return;
    check_posix(write(out_fd, buffer, (size_t)n), "write");
}

static int get_syscall_nr(const char *name) {
    int result = seccomp_syscall_resolve_name(name);
    if (result == __NR_SCMP_ERROR) {
        errx(EXIT_FAILURE, "non-existent syscall: %s", name);
    }
    return result;
}

_Noreturn static void usage(FILE *out) {
    fprintf(out, "usage: %s [options] [root] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
          " -h, --help                  display this help\n"
          " -v, --version               display version\n"
          " -p, --mount-proc            mount /proc in the container\n"
          "     --mount-dev             mount /dev as devtmpfs in the container\n"
          " -b, --bind                  bind mount a read-only directory in the container\n"
          " -B, --bind-rw               bind mount a directory in the container\n"
          " -u, --user=USER             the user to run the program as\n"
          " -n, --hostname=NAME         the hostname to set the container to\n"
          " -t, --timeout=INTEGER       how long the container is allowed to run\n"
          " -m, --memory-limit=LIMIT    the memory limit of the container\n"
          " -d, --devices=LIST          comma-separated whitelist of devices\n"
          " -s, --syscalls=LIST         comma-separated whitelist of syscalls\n"
          " -S, --syscalls-file=PATH    whitelist file containing one syscall name per line\n"
          " -l, --learn=PATH            allow unwhitelisted syscalls and append them to a file\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    check_posix(flags, "fcntl");
    check_posix(fcntl(fd, F_SETFL, flags | O_NONBLOCK), "fcntl");
}

// Mark any extra file descriptors `CLOEXEC`. Only `stdin`, `stdout` and `stderr` are left open.
static void prevent_leaked_file_descriptors() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) err(EXIT_FAILURE, "opendir");
    struct dirent *dp;
    while ((dp = readdir(dir))) {
        char *end;
        int fd = (int)strtol(dp->d_name, &end, 10);
        if (*end == '\0' && fd > 2 && fd != dirfd(dir)) {
            check_posix(ioctl(fd, FIOCLEX), "ioctl");
        }
    }
    closedir(dir);
}

static long strtolx_positive(const char *s, const char *what) {
    char *end;
    errno = 0;
    long result = strtol(s, &end, 10);
    if (errno) errx(EXIT_FAILURE, "%s is too large", what);
    if (*end != '\0' || result < 0)
        errx(EXIT_FAILURE, "%s must be a positive integer", what);
    return result;
}

static void do_trace(const struct signalfd_siginfo *si, bool *trace_init, FILE *learn) {
    int status;
    if (waitpid((pid_t)si->ssi_pid, &status, WNOHANG) != (pid_t)si->ssi_pid)
        errx(EXIT_FAILURE, "waitpid");

    if (WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status))
        errx(EXIT_FAILURE, "unexpected ptrace event");

    int inject_signal = 0;
    if (*trace_init) {
        int signal = WSTOPSIG(status);
        if (signal != SIGTRAP || !(status & PTRACE_EVENT_SECCOMP))
            inject_signal = signal;
        else {
            errno = 0;
#ifdef __x86_64__
            long syscall = ptrace(PTRACE_PEEKUSER, si->ssi_pid, sizeof(long) * ORIG_RAX);
#else
            long syscall = ptrace(PTRACE_PEEKUSER, si->ssi_pid, sizeof(long) * ORIG_EAX);
#endif
            if (errno) err(EXIT_FAILURE, "ptrace");
            char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);
            if (!name) errx(EXIT_FAILURE, "seccomp_syscall_resolve_num_arch");

            rewind(learn);
            char line[SYSCALL_NAME_MAX];
            while (fgets(line, sizeof(line), learn)) {
                char *pos;
                if ((pos = strchr(line, '\n'))) *pos = '\0';
                if (!strcmp(name, line)) {
                    name = NULL;
                    break;
                }
            }

            if (name) {
                fprintf(learn, "%s\n", name);
                free(name);
            }
        }
    } else {
        check_posix(ptrace(PTRACE_SETOPTIONS, si->ssi_pid, 0, PTRACE_O_TRACESECCOMP), "ptrace");
        *trace_init = true;
    }
    check_posix(ptrace(PTRACE_CONT, si->ssi_pid, 0, inject_signal), "ptrace");
}

static void handle_signal(int sig_fd, sd_bus *connection, const char *unit_name,
                          bool *trace_init, FILE *learn) {
    struct signalfd_siginfo si;
    ssize_t bytes_r = read(sig_fd, &si, sizeof(si));
    check_posix(bytes_r, "read");

    if (bytes_r != sizeof(si))
        errx(EXIT_FAILURE, "read the wrong amount of bytes");

    switch (si.ssi_signo) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        stop_scope_unit(connection, unit_name);
        errx(EXIT_FAILURE, "interrupted, stopping early");
    }

    if (si.ssi_signo != SIGCHLD)
        errx(EXIT_FAILURE, "got an unexpected signal");

    switch (si.ssi_code) {
    case CLD_EXITED:
        if (si.ssi_status) {
            warnx("application terminated with error code %d", si.ssi_status);
        }
        exit(si.ssi_status);
    case CLD_KILLED:
    case CLD_DUMPED:
        errx(EXIT_FAILURE, "application terminated abnormally with signal %d (%s)",
             si.ssi_status, strsignal(si.ssi_status));
    case CLD_TRAPPED:
        do_trace(&si, trace_init, learn);
    case CLD_STOPPED:
    default:
        break;
    }
}

int main(int argc, char **argv) {
    prevent_leaked_file_descriptors();

    bool mount_proc = false;
    bool mount_dev = false;
    const char *username = "nobody";
    const char *hostname = "playpen";
    long timeout = 0;
    long memory_limit = 128;
    struct bind_list *binds = NULL, *binds_tail = NULL;
    char *devices = NULL;
    char *syscalls = NULL;
    const char *syscalls_file = NULL;
    const char *learn_name = NULL;

    static const struct option opts[] = {
        { "help",          no_argument,       0, 'h' },
        { "version",       no_argument,       0, 'v' },
        { "mount-proc",    no_argument,       0, 'p' },
        { "mount-dev",     no_argument,       0, 0x100 },
        { "bind",          required_argument, 0, 'b' },
        { "bind-rw",       required_argument, 0, 'B' },
        { "user",          required_argument, 0, 'u' },
        { "hostname",      required_argument, 0, 'n' },
        { "timeout",       required_argument, 0, 't' },
        { "memory-limit",  required_argument, 0, 'm' },
        { "devices",       required_argument, 0, 'd' },
        { "syscalls",      required_argument, 0, 's' },
        { "syscalls-file", required_argument, 0, 'S' },
        { "learn",         required_argument, 0, 'l' },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int opt = getopt_long(argc, argv, "hvpb:B:u:n:t:m:d:s:S:l:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
        case 'v':
            printf("%s %s\n", program_invocation_short_name, VERSION);
            return 0;
        case 'p':
            mount_proc = true;
            break;
        case 0x100:
            mount_dev = true;
            break;
        case 'b':
        case 'B':
            if (binds) {
                binds_tail->next = bind_list_alloc(optarg, opt == 'b');
                binds_tail = binds_tail->next;
            } else {
                binds = binds_tail = bind_list_alloc(optarg, opt == 'b');
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'n':
            hostname = optarg;
            break;
        case 't':
            timeout = strtolx_positive(optarg, "timeout");
            break;
        case 'm':
            memory_limit = strtolx_positive(optarg, "memory limit");
            break;
        case 'd':
            devices = optarg;
            break;
        case 's':
            syscalls = optarg;
            break;
        case 'S':
            syscalls_file = optarg;
            break;
        case 'l':
            learn_name = optarg;
            break;
        default:
            usage(stderr);
        }
    }

    if (argc - optind < 2) {
        usage(stderr);
    }

    const char *root = argv[optind];
    optind++;

    scmp_filter_ctx ctx = seccomp_init(learn_name ? SCMP_ACT_TRACE(0) : SCMP_ACT_KILL);
    if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

    if (syscalls_file) {
        char name[SYSCALL_NAME_MAX];
        FILE *file = fopen(syscalls_file, "r");
        if (!file) err(EXIT_FAILURE, "failed to open syscalls file: %s", syscalls_file);
        while (fgets(name, sizeof(name), file)) {
            char *pos;
            if ((pos = strchr(name, '\n'))) *pos = '\0';
            check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(name), 0));
        }
        fclose(file);
    }

    check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0));

    if (syscalls) {
        for (char *s_ptr = syscalls, *saveptr; ; s_ptr = NULL) {
            const char *syscall = strtok_r(s_ptr, ",", &saveptr);
            if (!syscall) break;
            check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(syscall), 0));
        }
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    check_posix(epoll_fd, "epoll_create1");

    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    check_posix(sigprocmask(SIG_BLOCK, &mask, &old_mask), "sigprocmask");

    int sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    check_posix(sig_fd, "signalfd");

    epoll_add(epoll_fd, sig_fd, EPOLLIN);

    int pipe_in[2];
    int pipe_out[2];
    int pipe_err[2];
    check_posix(pipe(pipe_in), "pipe");
    check_posix(pipe(pipe_out), "pipe");
    set_non_blocking(pipe_out[0]);
    check_posix(pipe(pipe_err), "pipe");
    set_non_blocking(pipe_err[0]);

    int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO,
                       &(struct epoll_event){ .data.fd = STDIN_FILENO, .events = EPOLLIN });
    if (rc == -1 && errno != EPERM) err(EXIT_FAILURE, "epoll_ctl");
    const bool stdin_non_epoll = rc == -1;

    epoll_add(epoll_fd, pipe_out[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_err[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_in[1], EPOLLET | EPOLLOUT);

    unsigned long flags = SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET;
    pid_t pid = (pid_t)syscall(__NR_clone, flags, NULL);
    check_posix(pid, "clone");

    if (pid == 0) {
        dup2(pipe_in[0], STDIN_FILENO);
        close(pipe_in[0]);
        close(pipe_in[1]);

        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_out[0]);
        close(pipe_out[1]);

        dup2(pipe_err[1], STDERR_FILENO);
        close(pipe_err[0]);
        close(pipe_err[1]);

        // Kill this process if the parent dies. This is not a replacement for killing the sandboxed
        // processes via a control group as it is not inherited by child processes, but is more
        // robust when the sandboxed process is not allowed to fork.
        check_posix(prctl(PR_SET_PDEATHSIG, SIGKILL), "prctl");

        // Wait until the scope unit is set up before moving on. This also ensures that the parent
        // didn't die before `prctl` was called.
        uint8_t ready;
        check_posix(read(STDIN_FILENO, &ready, sizeof(ready)), "read");

        check_posix(sethostname(hostname, strlen(hostname)), "sethostname");

        // avoid propagating mounts to or from the parent's mount namespace
        mountx(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        mountx(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        mountx(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        if (mount_proc) {
            char *mnt = join_path(root, "proc");
            mountx(NULL, mnt, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
            free(mnt);
        }

        if (mount_dev) {
            char *mnt = join_path(root, "dev");
            mountx(NULL, mnt, "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
            free(mnt);
        }

        char *shm = join_path(root, "dev/shm");
        if (mount(NULL, shm, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
            if (errno != ENOENT) {
                err(EXIT_FAILURE, "mounting /dev/shm failed");
            }
        }
        free(shm);

        char *tmp = join_path(root, "tmp");
        if (mount(NULL, tmp, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
            if (errno != ENOENT) {
                err(EXIT_FAILURE, "mounting /tmp failed");
            }
        }
        free(tmp);

        bind_list_apply(root, binds);

        // preserve a reference to the target directory
        check_posix(chdir(root), "chdir");

        // make the working directory into the root of the mount namespace
        mountx(".", "/", NULL, MS_MOVE, NULL);

        // chroot into the root of the mount namespace
        check_posix(chroot("."), "chroot into `%s` failed", root);
        check_posix(chdir("/"), "entering chroot `%s` failed", root);

        errno = 0;
        struct passwd *pw = getpwnam(username);
        if (!pw) {
            if (errno) {
                err(EXIT_FAILURE, "getpwnam");
            } else {
                errx(EXIT_FAILURE, "no passwd entry for username %s", username);
            }
        }

        mountx(NULL, pw->pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        // switch to the user's home directory as a login shell would
        check_posix(chdir(pw->pw_dir), "chdir");

        // create a new session
        check_posix(setsid(), "setsid");

        check_posix(initgroups(username, pw->pw_gid), "initgroups");
        check_posix(setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid), "setresgid");
        check_posix(setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid), "setresuid");

        check_posix(sigprocmask(SIG_SETMASK, &old_mask, NULL), "sigprocmask");

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL, NULL, NULL, NULL};
        if ((asprintf(env + 1, "HOME=%s", pw->pw_dir) < 0 ||
             asprintf(env + 2, "USER=%s", username) < 0 ||
             asprintf(env + 3, "LOGNAME=%s", username) < 0)) {
            errx(EXIT_FAILURE, "asprintf");
        }

        if (learn_name) check_posix(ptrace(PTRACE_TRACEME, 0, NULL, NULL), "ptrace");

        check(seccomp_load(ctx));
        check_posix(execvpe(argv[optind], argv + optind, env), "execvpe");
    }

    bind_list_free(binds);
    seccomp_release(ctx);

    FILE *learn = NULL;
    if (learn_name) {
        learn = fopen(learn_name, "a+");
        if (!learn) err(EXIT_FAILURE, "fopen");
    }

    sd_bus *connection;
    check(sd_bus_open_system(&connection));

    char unit_name[100];
    snprintf(unit_name, sizeof(unit_name), "playpen-%u.scope", getpid());

    start_scope_unit(connection, pid, memory_limit, devices, unit_name);

    // Inform the child that the scope unit has been created.
    check_posix(write(pipe_in[1], &(uint8_t) { 0 }, 1), "write");
    set_non_blocking(pipe_in[1]);

    int timer_fd = -1;
    if (timeout) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        check_posix(timer_fd, "timerfd_create");
        epoll_add(epoll_fd, timer_fd, EPOLLIN);

        struct itimerspec spec = { .it_value = { .tv_sec = timeout } };
        check_posix(timerfd_settime(timer_fd, 0, &spec, NULL), "timerfd_settime");
    }

    uint8_t stdin_buffer[PIPE_BUF];
    ssize_t stdin_bytes_read = 0;
    bool trace_init = false;

    for (;;) {
        struct epoll_event events[8];
        int n_event = epoll_wait(epoll_fd, events, 4, -1);

        if (n_event < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "epoll_wait");
        }

        for (int i = 0; i < n_event; ++i) {
            struct epoll_event *evt = &events[i];

            if (evt->events & EPOLLERR) {
                close(evt->data.fd);
                continue;
            }

            if (evt->events & EPOLLIN) {
                if (evt->data.fd == timer_fd) {
                    warnx("timeout triggered!");
                    stop_scope_unit(connection, unit_name);
                    return EXIT_FAILURE;
                } else if (evt->data.fd == sig_fd) {
                    handle_signal(sig_fd, connection, unit_name, &trace_init, learn);
                } else if (evt->data.fd == pipe_out[0]) {
                    copy_to_stdstream(pipe_out[0], STDOUT_FILENO);
                } else if (evt->data.fd == pipe_err[0]) {
                    copy_to_stdstream(pipe_err[0], STDERR_FILENO);
                } else if (evt->data.fd == STDIN_FILENO) {
                    stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof(stdin_buffer));
                    check_posix(stdin_bytes_read, "read");
                    if (stdin_bytes_read == 0) {
                        check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        close(STDIN_FILENO);
                        close(pipe_in[1]);
                        continue;
                    }
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) {
                        check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        continue;
                    }
                    stdin_bytes_read = 0;
                    continue;
                }
            }

            // the child process is ready for more input
            if (evt->events & EPOLLOUT && evt->data.fd == pipe_in[1]) {
                // deal with previously buffered data
                if (stdin_bytes_read > 0) {
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) continue;
                    stdin_bytes_read = 0;

                    if (!stdin_non_epoll) {
                        epoll_add(epoll_fd, STDIN_FILENO, EPOLLIN); // accept more data
                    }
                }

                if (stdin_non_epoll) {
                    // drain stdin until a write would block
                    for (;;) {
                        stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof(stdin_buffer));
                        check_posix(stdin_bytes_read, "read");
                        ssize_t bytes_written = write(pipe_in[1], stdin_buffer,
                                                      (size_t)stdin_bytes_read);
                        if (check_eagain(bytes_written, "write")) break;

                        if (stdin_bytes_read < (ssize_t)sizeof(stdin_buffer)) {
                            close(STDIN_FILENO);
                            close(pipe_in[1]);
                            break;
                        }
                    }
                    continue;
                }
            }

            if (evt->events & EPOLLHUP) {
                if (evt->data.fd == STDIN_FILENO) {
                    close(pipe_in[1]);
                    check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                "epoll_ctl");
                }
                close(evt->data.fd);
            }
        }
    }
}
