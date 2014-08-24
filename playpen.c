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

#include <gio/gio.h>
#include <seccomp.h>
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

static void mountx(const char *source, const char *target, const char *filesystemtype,
                   unsigned long mountflags, const void *data) {
    check_posix(mount(source, target, filesystemtype, mountflags, data),
                "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

struct bind_list {
    struct bind_list *next;
    char arg[];
};

static struct bind_list *bind_list_alloc(const char *arg) {
    size_t len = strlen(arg);
    struct bind_list *next = malloc(sizeof(struct bind_list) + len + 1);
    if (!next) err(EXIT_FAILURE, "malloc");

    next->next = NULL;
    strcpy(next->arg, arg);
    return next;
}

static void bind_list_apply(struct bind_list *list, bool read_only) {
    for (; list; list = list->next) {
        char *dst;
        check_posix(asprintf(&dst, "./%s", list->arg), "asprintf");
        mountx(list->arg, dst, "bind", MS_BIND|MS_REC, NULL);
        if (read_only)
            mountx(list->arg, dst, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);
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

static GDBusConnection *get_system_bus() {
    GError *error = NULL;
    GDBusConnection *connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) errx(EXIT_FAILURE, "%s", error->message);
    return connection;
}

static void wait_for_unit(pid_t child_pid, const char *expected_name) {
    for (;;) {
        char *unit;
        check(sd_pid_get_unit(child_pid, &unit));
        bool equal = !strcmp(expected_name, unit);
        free(unit);
        if (equal) break;
    }
}

static void start_scope_unit(GDBusConnection *connection, pid_t child_pid, long memory_limit,
                             char *devices, const char *unit_name) {
    GVariantBuilder *pids = g_variant_builder_new(G_VARIANT_TYPE("au"));
    g_variant_builder_add(pids, "u", child_pid);

    GVariantBuilder *allowed = g_variant_builder_new(G_VARIANT_TYPE("a(ss)"));

    if (devices) {
        for (char *s_ptr = devices, *saveptr; ; s_ptr = NULL) {
            const char *device = strtok_r(s_ptr, ",", &saveptr);
            if (!device) break;
            char *split = strchr(device, ':');
            if (!split) errx(EXIT_FAILURE, "invalid device parameter `%s`", device);
            *split = '\0';
            g_variant_builder_add(allowed, "(ss)", device, split + 1);
        }
    }

    GVariantBuilder *properties = g_variant_builder_new(G_VARIANT_TYPE("a(sv)"));
    g_variant_builder_add(properties, "(sv)", "Description",
                          g_variant_new("s", "Playpen application sandbox"));
    g_variant_builder_add(properties, "(sv)", "PIDs", g_variant_new("au", pids));
    g_variant_builder_add(properties, "(sv)", "MemoryLimit",
                          g_variant_new("t", 1024ULL * 1024ULL * (unsigned long long)memory_limit));
    g_variant_builder_add(properties, "(sv)", "DevicePolicy", g_variant_new("s", "strict"));
    g_variant_builder_add(properties, "(sv)", "DeviceAllow", g_variant_new("a(ss)", allowed));
    g_variant_builder_add(properties, "(sv)", "CPUAccounting", g_variant_new("b", TRUE));
    g_variant_builder_add(properties, "(sv)", "BlockIOAccounting", g_variant_new("b", TRUE));

    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(connection, systemd_bus_name, systemd_path_name,
                                                  manager_interface, "StartTransientUnit",
                                                  g_variant_new("(ssa(sv)a(sa(sv)))",
                                                                unit_name,
                                                                "fail",
                                                                properties,
                                                                NULL),
                                                  G_VARIANT_TYPE("(o)"),
                                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
    if (error) errx(EXIT_FAILURE, "%s", error->message);
    g_variant_unref(reply);
    wait_for_unit(child_pid, unit_name);
}

// NoSuchUnit errors are expected as the contained processes can die at any point.
static bool is_unexpected_stop_unit_error(GError *error) {
    if (!g_dbus_error_is_remote_error(error)) return false;
    char *name = g_dbus_error_get_remote_error(error);
    bool ret = strcmp(name, "org.freedesktop.systemd1.NoSuchUnit");
    g_free(name);
    return ret;
}

static void stop_scope_unit(GDBusConnection *connection, const char *unit_name) {
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(connection, systemd_bus_name, systemd_path_name,
                                                  manager_interface, "StopUnit",
                                                  g_variant_new("(ss)", unit_name, "fail"),
                                                  G_VARIANT_TYPE("(o)"),
                                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
    if (error) {
        if (is_unexpected_stop_unit_error(error))
            errx(EXIT_FAILURE, "%s", error->message);
        g_error_free(error);
    } else
        g_variant_unref(reply);
}

static void epoll_add(int epoll_fd, int fd, uint32_t events) {
    struct epoll_event event = { .data.fd = fd, .events = events };
    check_posix(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event), "epoll_ctl");
}

// This could often use `splice`, but it will not always work with `stdout` and `stderr`.
static void copy_pipe_to(int in_fd, int out_fd) {
    ssize_t n;
    do {
        uint8_t buffer[BUFSIZ];
        n = read(in_fd, buffer, sizeof buffer);
        if (check_eagain(n, "read")) return;
        check_posix(write(out_fd, buffer, (size_t)n), "write");
    } while (n != 0);
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
          "     --bind                  bind mount a read-only directory in the container\n"
          "     --bind-rw               bind mount a directory in the container\n"
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
    if (*trace_init) {
        errno = 0;
        long syscall = ptrace(PTRACE_PEEKUSER, si->ssi_pid, sizeof(long)*ORIG_RAX);
        if (errno) err(EXIT_FAILURE, "ptrace");
        char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);

        rewind(learn);
        char line[SYSCALL_NAME_MAX];
        while (fgets(line, sizeof line, learn)) {
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
    } else {
        check_posix(ptrace(PTRACE_SETOPTIONS, si->ssi_pid, 0, PTRACE_O_TRACESECCOMP), "ptrace");
        *trace_init = true;
    }
    check_posix(ptrace(PTRACE_CONT, si->ssi_pid, 0, 0), "ptrace");
}

static void handle_signal(int sig_fd, GDBusConnection *connection, const char *unit_name,
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
    g_log_set_always_fatal(G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL);

    prevent_leaked_file_descriptors();

    bool mount_proc = false;
    bool mount_dev = false;
    const char *username = "nobody";
    const char *hostname = "playpen";
    long timeout = 0;
    long memory_limit = 128;
    struct bind_list *binds = NULL, *binds_tail = NULL;
    struct bind_list *rw_binds = NULL, *rw_binds_tail = NULL;
    char *devices = NULL;
    char *syscalls = NULL;
    const char *syscalls_file = NULL;
    const char *learn_name = NULL;

    static const struct option opts[] = {
        { "help",          no_argument,       0, 'h' },
        { "version",       no_argument,       0, 'v' },
        { "mount-proc",    no_argument,       0, 'p' },
        { "mount-dev",     no_argument,       0, 0x100 },
        { "bind",          required_argument, 0, 0x101 },
        { "bind-rw",       required_argument, 0, 0x102 },
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
        int opt = getopt_long(argc, argv, "hvpu:r:n:t:m:d:s:S:l:", opts, NULL);
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
        case 0x101:
            if (binds) {
                binds_tail->next = bind_list_alloc(optarg);
                binds_tail = binds_tail->next;
            } else {
                binds = binds_tail = bind_list_alloc(optarg);
            }
            break;
        case 0x102:
            if (rw_binds) {
                rw_binds_tail->next = bind_list_alloc(optarg);
                rw_binds_tail = rw_binds_tail->next;
            } else {
                rw_binds = rw_binds_tail = bind_list_alloc(optarg);
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
        while (fgets(name, sizeof name, file)) {
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

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    check_posix(sigprocmask(SIG_BLOCK, &mask, NULL), "sigprocmask");

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
        check_posix(read(STDIN_FILENO, &ready, sizeof ready), "read");

        check_posix(sethostname(hostname, strlen(hostname)), "sethostname");

        // avoid propagating mounts to or from the parent's mount namespace
        mountx(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        mountx(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        mountx(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        // preserve a reference to the target directory
        check_posix(chdir(root), "chdir");

        if (mount_proc) {
            mountx(NULL, "proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
        }
        if (mount_dev) {
            mountx(NULL, "dev", "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
        }
        mountx(NULL, "dev/shm", "tmpfs", MS_NOSUID|MS_NODEV, NULL);
        mountx(NULL, "tmp", "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        bind_list_apply(binds, true);
        bind_list_apply(rw_binds, false);

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
    bind_list_free(rw_binds);
    seccomp_release(ctx);

    FILE *learn = NULL;
    if (learn_name) {
        learn = fopen(learn_name, "a+");
        if (!learn) err(EXIT_FAILURE, "fopen");
    }

    GDBusConnection *connection = get_system_bus();

    char unit_name[100];
    snprintf(unit_name, sizeof unit_name, "playpen-%u.scope", getpid());

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
        struct epoll_event events[4];
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
                    copy_pipe_to(pipe_out[0], STDOUT_FILENO);
                } else if (evt->data.fd == pipe_err[0]) {
                    copy_pipe_to(pipe_err[0], STDERR_FILENO);
                } else if (evt->data.fd == STDIN_FILENO) {
                    stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof stdin_buffer);
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
                        stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof stdin_buffer);
                        check_posix(stdin_bytes_read, "read");
                        ssize_t bytes_written = write(pipe_in[1], stdin_buffer,
                                                      (size_t)stdin_bytes_read);
                        if (check_eagain(bytes_written, "write")) break;

                        if (stdin_bytes_read < (ssize_t)sizeof stdin_buffer) {
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
