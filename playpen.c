#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <linux/limits.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include <systemd/sd-login.h>
#include <gio/gio.h>
#include <seccomp.h>

static void check(int rc) {
    if (rc < 0) errx(1, "%s", strerror(-rc));
}

static void mountx(const char *source, const char *target, const char *filesystemtype,
                   unsigned long mountflags, const void *data) {
    if (mount(source, target, filesystemtype, mountflags, data) < 0)
        err(1, "mounting %s failed", target);
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

static void stop_scope_unit(GDBusConnection *connection, const char *unit_name) {
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(connection, systemd_bus_name, systemd_path_name,
                                                  manager_interface, "StopUnit",
                                                  g_variant_new("(ss)", unit_name, "fail"),
                                                  G_VARIANT_TYPE("(o)"),
                                                  G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
    if (error) errx(EXIT_FAILURE, "%s", error->message);
    g_variant_unref(reply);
}

static void epoll_watch(int epoll_fd, int fd) {
    struct epoll_event event = { .data.fd = fd, .events = EPOLLIN };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        err(1, "epoll_ctl");
}

// This could often use `splice`, but it will not always work with `stdout` and `stderr`.
static void copy_pipe_to(int in_fd, int out_fd) {
    ssize_t n;
    do {
        uint8_t buffer[BUFSIZ];
        n = read(in_fd, buffer, sizeof buffer);
        if (n == -1) {
            if (errno == EAGAIN) return;
            err(EXIT_FAILURE, "read");
        }
        if (write(out_fd, buffer, (size_t)n) == -1)
            err(EXIT_FAILURE, "write");
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
          " -u, --user=USER             the user to run the program as\n"
          " -n, --hostname=NAME         the hostname to set the container to\n"
          " -t, --timeout=INTEGER       how long the container is allowed to run\n"
          " -m, --memory-limit=LIMIT    the memory limit of the container\n"
          " -d, --devices=LIST          comma-separated whitelist of devices\n"
          " -s, --syscalls=LIST         comma-separated whitelist of syscalls\n"
          "     --syscalls-file=PATH    whitelist file containing one syscall name per line\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) err(EXIT_FAILURE, "fcntl");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        err(EXIT_FAILURE, "fcntl");
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
            if (ioctl(fd, FIOCLEX) == -1) err(EXIT_FAILURE, "ioctl");
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

static void pipex(int pipefd[2]) {
    if (pipe(pipefd) < 0) {
        err(EXIT_FAILURE, "pipe");
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
    char *devices = NULL;
    char *syscalls = NULL;
    const char *syscalls_file = NULL;
    int syscalls_from_file[500]; // upper bound on the number of syscalls

    static const struct option opts[] = {
        { "help",          no_argument,       0, 'h' },
        { "version",       no_argument,       0, 'v' },
        { "mount-proc",    no_argument,       0, 'p' },
        { "mount-dev",     no_argument,       0, 0x100 },
        { "user",          required_argument, 0, 'u' },
        { "hostname",      required_argument, 0, 'n' },
        { "timeout",       required_argument, 0, 't' },
        { "memory-limit",  required_argument, 0, 'm' },
        { "devices",       required_argument, 0, 'd' },
        { "syscalls",      required_argument, 0, 's' },
        { "syscalls-file", required_argument, 0, 0x101 },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvpu:r:n:t:m:d:s:", opts, NULL);
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
        case 0x101:
            syscalls_file = optarg;
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

    if (syscalls_file) {
        char name[30]; // longest syscall name
        FILE *file = fopen(syscalls_file, "r");
        if (!file) err(EXIT_FAILURE, "failed to open syscalls file: %s", syscalls_file);
        size_t i = 0;
        while (fgets(name, sizeof name / sizeof name[0], file)) {
            char *pos;
            if ((pos = strchr(name, '\n'))) *pos = '\0';
            syscalls_from_file[i++] = get_syscall_nr(name);
        }
        syscalls_from_file[i] = -1;
        fclose(file);
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        err(1, "epoll");
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        err(1, "sigprocmask");
    }

    epoll_watch(epoll_fd, STDIN_FILENO);

    int sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (sig_fd < 0) {
        err(1, "signalfd");
    }

    epoll_watch(epoll_fd, sig_fd);

    int timer_fd = -1;
    if (timeout) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
        if (timer_fd < 0)
            err(EXIT_FAILURE, "timerfd_create");

        epoll_watch(epoll_fd, timer_fd);
    }

    int pipe_in[2];
    int pipe_out[2];
    int pipe_err[2];
    pipex(pipe_in);
    pipex(pipe_out);
    set_non_blocking(pipe_out[0]);
    pipex(pipe_err);
    set_non_blocking(pipe_err[0]);

    // A pipe for signalling that the scope unit is set up.
    int pipe_ready[2];
    if (pipe2(pipe_ready, O_CLOEXEC) < 0) {
        err(1, "pipe");
    }

    epoll_watch(epoll_fd, pipe_out[0]);
    epoll_watch(epoll_fd, pipe_err[0]);

    unsigned long flags = SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET;
    pid_t pid = (pid_t)syscall(__NR_clone, flags, NULL);

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

        close(pipe_ready[1]);

        // Kill this process if the parent dies. This is not a replacement for killing the sandboxed
        // processes via a control group as it is not inherited by child processes, but is more
        // robust when the sandboxed process is not allowed to fork.
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        // Wait until the scope unit is set up before moving on. This also ensures that the parent
        // didn't die before `prctl` was called.
        uint8_t ready;
        if (read(pipe_ready[0], &ready, sizeof ready) == -1) {
            err(EXIT_FAILURE, "read");
        }
        close(pipe_ready[0]);

        if (sethostname(hostname, strlen(hostname)) < 0) {
            err(1, "sethostname");
        }

        // avoid propagating mounts to or from the real root
        mountx(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        mountx(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        mountx(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        if (chroot(root) < 0 || chdir("/") < 0) {
            err(1, "entering chroot `%s` failed", root);
        }

        if (mount_proc) {
            mountx(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
        }
        if (mount_dev) {
            mountx(NULL, "/dev", "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
        }
        mountx(NULL, "/dev/shm", "tmpfs", MS_NOSUID|MS_NODEV, NULL);
        mountx(NULL, "/tmp", "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        errno = 0;
        struct passwd *pw = getpwnam(username);
        if (!pw) {
            if (errno) {
                err(1, "getpwnam");
            } else {
                errx(1, "no passwd entry for username %s", username);
            }
        }

        mountx(NULL, pw->pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        // switch to the user's home directory as a login shell would
        if (chdir(pw->pw_dir)) {
            err(1, "chdir");
        }

        // create a new session
        if (setsid() < 0) {
            err(1, "setsid");
        }

        if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) {
            err(1, "setresgid");
        }
        if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
            err(1, "setresuid");
        }

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL, NULL, NULL, NULL};
        if ((asprintf(env + 1, "HOME=%s", pw->pw_dir) < 0 ||
             asprintf(env + 2, "USER=%s", username) < 0 ||
             asprintf(env + 3, "LOGNAME=%s", username) < 0)) {
            errx(1, "asprintf");
        }

        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
            return 1;
        }

        check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0));

        if (syscalls) {
            for (char *s_ptr = syscalls, *saveptr; ; s_ptr = NULL) {
                const char *syscall = strtok_r(s_ptr, ",", &saveptr);
                if (!syscall) break;
                check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(syscall), 0));
            }
        }

        for (size_t i = 0; i < sizeof syscalls_from_file / sizeof syscalls_from_file[0]; i++) {
            if (syscalls_from_file[i] == -1) break;
            check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls_from_file[i], 0));
        }

        check(seccomp_load(ctx));

        if (execvpe(argv[optind], argv + optind, env) < 0) {
            err(1, "execvpe");
        }
    } else if (pid < 0) {
        err(1, "clone");
    }

    GDBusConnection *connection = get_system_bus();

    char unit_name[100];
    snprintf(unit_name, sizeof unit_name, "playpen-%u.scope", getpid());

    start_scope_unit(connection, pid, memory_limit, devices, unit_name);

    if (write(pipe_ready[1], &(uint8_t) { 0 }, 1) == -1) {
        err(EXIT_FAILURE, "write");
    }

    if (timeout) {
        struct itimerspec spec = { .it_value = { .tv_sec = timeout } };
        if (timerfd_settime(timer_fd, 0, &spec, NULL) < 0)
            err(EXIT_FAILURE, "timerfd_settime");
    }

    struct epoll_event events[4];

    while (true) {
        int i, n = epoll_wait(epoll_fd, events, 4, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            err(1, "epoll_wait");
        }

        for (i = 0; i < n; ++i) {
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
                    struct signalfd_siginfo si;
                    ssize_t bytes_r = read(sig_fd, &si, sizeof(si));

                    if (bytes_r < 0) {
                        err(1, "read");
                    } else if (bytes_r != sizeof(si)) {
                        errx(EXIT_FAILURE, "read the wrong amount of bytes");
                    } else if (si.ssi_signo != SIGCHLD) {
                        errx(EXIT_FAILURE, "got an unexpected signal");
                    }

                    switch (si.ssi_code) {
                    case CLD_EXITED:
                        if (si.ssi_status) {
                            warnx("application terminated with error code %d", si.ssi_status);
                        }
                        return si.ssi_status;
                    case CLD_KILLED:
                    case CLD_DUMPED:
                        errx(EXIT_FAILURE, "application terminated abnormally with signal %d (%s)",
                             si.ssi_status, strsignal(si.ssi_status));
                    case CLD_TRAPPED:
                    case CLD_STOPPED:
                    default:
                        break;
                    }
                } else if (evt->data.fd == pipe_out[0]) {
                    copy_pipe_to(pipe_out[0], STDOUT_FILENO);
                } else if (evt->data.fd == pipe_err[0]) {
                    copy_pipe_to(pipe_err[0], STDERR_FILENO);
                } else if (evt->data.fd == STDIN_FILENO) {
                    uint8_t buffer[BUFSIZ];
                    ssize_t n = read(STDIN_FILENO, buffer, sizeof buffer);
                    if (n == -1) {
                        err(EXIT_FAILURE, "read");
                    }
                    if (n == 0) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                        close(STDIN_FILENO);
                        close(pipe_in[1]);
                    } else if (write(pipe_in[1], buffer, (size_t)n) == -1) {
                        err(EXIT_FAILURE, "write");
                    }
                }
            }

            if (evt->events & EPOLLHUP) {
                if (evt->data.fd == STDIN_FILENO) {
                    close(pipe_in[1]);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                }
                close(evt->data.fd);
            }
        }
    }
}
