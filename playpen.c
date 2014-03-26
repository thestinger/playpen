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

#include <seccomp.h>

static FILE *fopenx(const char *path, const char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) err(EXIT_FAILURE, "failed to open %s", path);
    return f;
}

static void mountx(const char *source, const char *target, const char *filesystemtype,
                   unsigned long mountflags, const void *data) {
    if (mount(source, target, filesystemtype, mountflags, data) < 0) {
        err(1, "mounting %s failed", target);
    }
}

static void write_to(const char *path, const char *string) {
    FILE *fp = fopenx(path, "w");
    fputs(string, fp);
    fclose(fp);
}

static void init_cgroup(pid_t ppid, const char *memory_limit, char *devices) {
    char path[PATH_MAX];

    if (mkdir("/sys/fs/cgroup/memory/playpen", 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create memory cgroup");
    }

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/playpen/%jd", (intmax_t)ppid);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create memory cgroup");
    }

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/playpen/%jd/cgroup.procs", (intmax_t)ppid);
    write_to(path, "0");

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/playpen/%jd/memory.limit_in_bytes", (intmax_t)ppid);
    write_to(path, memory_limit);

    if (mkdir("/sys/fs/cgroup/devices/playpen", 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create device cgroup");
    }

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/devices/playpen/%jd", (intmax_t)ppid);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create device cgroup");
    }

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/devices/playpen/%jd/cgroup.procs", (intmax_t)ppid);
    write_to(path, "0");

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/devices/playpen/%jd/devices.deny", (intmax_t)ppid);
    write_to(path, "a");

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/devices/playpen/%jd/devices.allow", (intmax_t)ppid);

    if (devices) {
        for (char *s_ptr = devices, *saveptr; ; s_ptr = NULL) {
            const char *device = strtok_r(s_ptr, ",", &saveptr);
            if (!device) break;
            char type;
            unsigned major, minor;
            int read;
            if ((sscanf(device, "%c:%u:%u%n", &type, &major, &minor, &read) != 3 ||
                 device[read] != '\0')) {
                errx(1, "invalid device: %s", device);
            }
            FILE *fp = fopenx(path, "w");
            fprintf(fp, "%c %u:%u r", type, major, minor);
            fclose(fp);
        }
    }
}

static void epoll_watch(int epoll_fd, int fd) {
    struct epoll_event event = {};
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        err(1, "epoll_ctl");
}

static void copy_pipe_to(int in_fd, int out_fd) {
    while (true) {
        ssize_t bytes_s = splice(in_fd, NULL, out_fd, NULL, BUFSIZ,
                                 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (bytes_s < 0) {
            if (errno == EAGAIN)
                break;
            err(1, "splice");
        }
    }
}

static void kill_group() {
    pid_t pid = getpid();
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/playpen/%jd/cgroup.procs", (intmax_t)pid);

    bool done = false;
    do {
        FILE *proc = fopenx(path, "r");
        pid_t pid;
        done = true;
        while (fscanf(proc, "%u", &pid) == 1) {
            kill(pid, SIGKILL);
            done = false;
        }
        fclose(proc);
    } while (!done);

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/memory/playpen/%jd", (intmax_t)pid);
    if (rmdir(path) < 0 && errno != ENOENT) {
        err(1, "rmdir");
    }

    snprintf(path, PATH_MAX, "/sys/fs/cgroup/devices/playpen/%jd", (intmax_t)pid);
    if (rmdir(path) < 0 && errno != ENOENT) {
        err(1, "rmdir");
    }
}

static int get_syscall_nr(const char *name) {
    int result = seccomp_syscall_resolve_name(name);
    if (result == __NR_SCMP_ERROR) {
        errx(EXIT_FAILURE, "non-existent syscall: %s", name);
    }
    return result;
}

__attribute__((noreturn)) static void usage(FILE *out) {
    fprintf(out, "usage: %s [options] [root] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
          " -h, --help                  display this help\n"
          " -v, --version               display version\n"
          " -u, --user=USER             the user to run the program as\n"
          " -n, --hostname=NAME         the hostname to set the container to\n"
          " -t, --timeout=INTEGER       how long the container is allowed to run\n"
          " -m  --memory-limit=LIMIT    the memory limit of the container\n"
          " -s, --syscalls=LIST         comma-separated whitelist of syscalls\n"
          "     --syscalls-file=PATH    whitelist file containing one syscall name per line\n"
          "     --devices=LIST          comma-separated whitelist of readable devices\n"
          "\n"
          "Devices are taken as `type:major:minor` where `type` is `c` (char) or\n"
          "`b` (block) and `major` and `minor` are integers.\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


static void check(int rc) {
    if (rc < 0) {
        errx(1, "%s", strerror(-rc));
    }
}

// Close any extra file descriptors. Only `stdin`, `stdout` and `stderr` are left open.
static void close_file_descriptors() {
     DIR *dir = opendir("/proc/self/fd");
     if (!dir) {
         err(EXIT_FAILURE, "opendir");
     }
     struct dirent *dp;
     while ((dp = readdir(dir)) != NULL) {
         char *end;
         int fd = strtol(dp->d_name, &end, 10);
         if (*end == '\0' && fd > 2 && fd != dirfd(dir)) {
             close(fd);
         }
     }
     closedir(dir);
}

int main(int argc, char **argv) {
    close_file_descriptors();

    int epoll_fd;
    const char *memory_limit = "128M";
    const char *username = "nobody";
    const char *hostname = "playpen";
    char *syscalls = NULL;
    char *devices = NULL;
    const char *syscalls_file = NULL;
    int syscalls_from_file[500]; // upper bound on the number of syscalls
    int timeout = 0;

    static const struct option opts[] = {
        { "help",          no_argument,       0, 'h' },
        { "version",       no_argument,       0, 'v' },
        { "user",          required_argument, 0, 'u' },
        { "hostname",      required_argument, 0, 'n' },
        { "timeout",       required_argument, 0, 't' },
        { "memory-limit",  required_argument, 0, 'm' },
        { "syscalls",      required_argument, 0, 's' },
        { "syscalls-file", required_argument, 0, 0x100 },
        { "devices",       required_argument, 0, 0x101 },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvu:r:n:t:m:s:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, VERSION);
            return 0;
        case 'u':
            username = optarg;
            break;
        case 'n':
            hostname = optarg;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'm':
            memory_limit = optarg;
            break;
        case 's':
            syscalls = optarg;
            break;
        case 0x100:
            syscalls_file = optarg;
            break;
        case 0x101:
            devices = optarg;
            break;
        default:
            usage(stderr);
            break;
        }
    }

    if (argc - optind < 2) {
        usage(stderr);
    }

    const char *root = argv[optind];
    optind++;

    if (syscalls_file) {
        char name[30]; // longest syscall name
        FILE *file = fopenx(syscalls_file, "r");
        size_t i = 0;
        while (fgets(name, sizeof name / sizeof name[0], file)) {
            char *pos;
            if ((pos = strchr(name, '\n'))) *pos = '\0';
            syscalls_from_file[i++] = get_syscall_nr(name);
        }
        syscalls_from_file[i] = -1;
        fclose(file);
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        err(1, "epoll");
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        err(1, "sigprocmask");
    }

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

    int pipe_out[2];
    int pipe_err[2];
    if (pipe(pipe_out) < 0) {
        err(1, "pipe");
    }

    if (pipe(pipe_err) < 0) {
        err(1, "pipe");
    }

    // A pipe for checking if this process is dead from the child.
    int pipe_parent_alive[2];
    if (pipe2(pipe_parent_alive, O_CLOEXEC) < 0) {
        err(1, "pipe");
    }

    epoll_watch(epoll_fd, pipe_out[0]);
    epoll_watch(epoll_fd, pipe_err[0]);

    pid_t ppid = getpid(); // getppid() in the child won't work

    if (unshare(CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET) < 0) {
        err(EXIT_FAILURE, "unshare");
    }

    pid_t pid = fork();

    if (pid == 0) {
        close(0);
        dup2(pipe_out[1], 1);
        dup2(pipe_err[1], 2);

        close(pipe_out[0]);
        close(pipe_out[1]);
        close(pipe_err[0]);
        close(pipe_err[1]);

        init_cgroup(ppid, memory_limit, devices);

        // Kill this process if the parent dies. This is not a replacement for killing the sandboxed
        // processes via a control group as it is not inherited by child processes, but is more
        // robust when the sandboxed process is not allowed to fork.
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        // Make sure the parent didn't die before calling `prctl`.
        close(pipe_parent_alive[0]);
        for (;;) {
            if (write(pipe_parent_alive[1], &(uint8_t) { 0 }, 1) == -1) {
                if (errno == EINTR) {
                    continue;
                } else {
                    err(EXIT_FAILURE, "write");
                }
            }
            break;
        }

        if (sethostname(hostname, strlen(hostname)) < 0) {
            err(1, "sethostname");
        }

        // avoid propagating mounts to or from the real root
        mountx(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        mountx(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        mountx(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        if (chroot(root) < 0) {
            err(1, "chroot");
        }

        if (chdir("/") < 0) {
            err(1, "chdir");
        }

        mountx(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
        mountx(NULL, "/dev/shm", "tmpfs", MS_NOSUID|MS_NODEV, NULL);
        mountx(NULL, "/tmp", "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        struct passwd pw;
        size_t buffer_len = sysconf(_SC_GETPW_R_SIZE_MAX);
        char *buffer = (char *)malloc(buffer_len);
        if (!buffer) {
            err(1, "malloc");
        }
        struct passwd *p_pw = &pw;
        int r = getpwnam_r(username, &pw, buffer, buffer_len, &p_pw);
        if (!p_pw) {
            if (r) {
                err(1, "getpwnam_r");
            } else {
                errx(1, "no passwd entry for username %s", username);
            }
        }

        mountx(NULL, pw.pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

        // switch to the user's home directory as a login shell would
        if (chdir(pw.pw_dir)) {
            err(1, "chdir");
        }

        // create a new session
        if (setsid() < 0) {
            err(1, "setsid");
        }

        if (setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid) < 0) {
            err(1, "setresgid");
        }
        if (setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid) < 0) {
            err(1, "setresuid");
        }

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL, NULL, NULL, NULL};
        if ((asprintf(env + 1, "HOME=%s", pw.pw_dir) < 0 ||
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
        err(1, "fork");
    }

    atexit(kill_group);

    if (timeout) {
        struct itimerspec spec = {};
        spec.it_value.tv_sec = timeout;

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

            if (evt->events & EPOLLERR || evt->events & EPOLLHUP) {
                close(evt->data.fd);
            } else if (evt->data.fd == timer_fd) {
                fprintf(stderr, "timeout triggered!\n");
                return 1;
            } else if (evt->data.fd == sig_fd) {
                struct signalfd_siginfo si;
                ssize_t bytes_r = read(sig_fd, &si, sizeof(si));

                if (bytes_r < 0) {
                    err(1, "read");
                } else if (bytes_r != sizeof(si)) {
                    fprintf(stderr, "read the wrong about of bytes\n");
                    return 1;
                } else if (si.ssi_signo != SIGCHLD) {
                    fprintf(stderr, "got an unexpected signal\n");
                    return 1;
                }

                switch (si.ssi_code) {
                case CLD_EXITED:
                    if (si.ssi_status) {
                        fprintf(stderr, "application terminated with error code %d\n", si.ssi_status);
                    }
                    return si.ssi_status;
                case CLD_KILLED:
                case CLD_DUMPED:
                    fprintf(stderr, "application terminated abnormally with signal %d (%s)\n",
                            si.ssi_status, strsignal(si.ssi_status));
                    return 1;
                case CLD_TRAPPED:
                case CLD_STOPPED:
                default:
                    break;
                }
            } else if (evt->data.fd == pipe_out[0]) {
                copy_pipe_to(pipe_out[0], 1);
            } else if (evt->data.fd == pipe_err[0]) {
                copy_pipe_to(pipe_err[0], 2);
            }
        }
    }
}
