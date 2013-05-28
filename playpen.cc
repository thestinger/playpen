#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <fstream>

#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <linux/limits.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include <seccomp.h>

static int epoll_fd;

static const char *username = "rust";
static const char *memory_limit = "128M";
static const char *root = "sandbox";
static const char *hostname = "playpen";
static int timeout = 0;

static void write_to(const char *path, const char *string) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        err(EXIT_FAILURE, "failed to open %s", path);
    }
    fputs(string, fp);
    fclose(fp);
}

static void init_cgroup() {
    if (mkdir("/sys/fs/cgroup/memory/playpen", 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create memory cgroup");
    }

    write_to("/sys/fs/cgroup/memory/playpen/tasks", "0");
    write_to("/sys/fs/cgroup/memory/playpen/memory.limit_in_bytes", memory_limit);

    if (mkdir("/sys/fs/cgroup/devices/playpen", 0755) < 0 && errno != EEXIST) {
        err(EXIT_FAILURE, "failed to create device cgroup");
    }

    write_to("/sys/fs/cgroup/devices/playpen/tasks", "0");
    write_to("/sys/fs/cgroup/devices/playpen/devices.deny", "a");
    write_to("/sys/fs/cgroup/devices/playpen/devices.allow", "c 1:9 rw"); // urandom
}

static void epoll_watch(int fd) {
    struct epoll_event event = {
        .data.fd = fd,
        .events  = EPOLLIN | EPOLLET
    };

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
        err(1, "epoll_ctl");
}

static void copy_pipe_to(int in_fd, int out_fd) {
    while (true) {
        ssize_t bytes_s = splice(in_fd, NULL, out_fd, NULL, BUFSIZ, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (bytes_s < 0) {
            if (errno == EAGAIN)
                break;
            err(1, "splice");
        }
    }
}

static void kill_group() {
    bool done = false;
    do {
        std::ifstream procs("/sys/fs/cgroup/memory/playpen/cgroup.procs");
        pid_t pid;
        done = true;
        while (procs >> pid) {
            kill(pid, SIGKILL);
            done = false;
        }
    } while (!done);

    if (rmdir("/sys/fs/cgroup/memory/playpen") < 0 && errno != ENOENT) {
        err(1, "rmdir");
    }
    if (rmdir("/sys/fs/cgroup/devices/playpen") < 0 && errno != ENOENT) {
        err(1, "rmdir");
    }
}

static void [[noreturn]] usage(FILE *out) {
    fprintf(out, "usage: %s [options] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
        " -h, --help                  display this help\n"
        " -v, --version               display version\n"
        " -u, --user=USER             the user to run the program as\n"
        " -r, --root=ROOT             the root of the container\n"
        " -n, --hostname=NAME         the hostname to set the container to\n"
        " -t, --timeout=NAME          how long the container is allowed to run\n"
        "     --memory-limit=LIMIT    the memory limit of the container\n", out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    static const struct option opts[] = {
        { "help",         no_argument,       0, 'h' },
        { "version",      no_argument,       0, 'v' },
        { "user",         required_argument, 0, 'u' },
        { "root",         required_argument, 0, 'r' },
        { "hostname",     required_argument, 0, 'n' },
        { "timeout",      required_argument, 0, 't' },
        { "memory-limit", required_argument, 0, 0x100 },
        { 0, 0, 0, 0 }
    };

    while (true) {
        int opt = getopt_long(argc, argv, "hvu:r:n:t:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
            break;
        case 'v':
            printf("%s %s\n", program_invocation_short_name, "devel");
            return 0;
        case 'u':
            username = optarg;
            break;
        case 'r':
            root = optarg;
            break;
        case 'n':
            hostname = optarg;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        default:
            usage(stderr);
            break;
        }
    }

    if (optind == 0) {
        errx(1, "need at least one argument (program to run in sandbox)");
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

    epoll_watch(sig_fd);

    int timer_fd = -1;
    if (timeout) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
        if (timer_fd < 0)
            err(EXIT_FAILURE, "timerfd_create");

        epoll_watch(timer_fd);
    }

    int pipe_out[2];
    int pipe_err[2];
    if (pipe(pipe_out) < 0) {
        err(1, "pipe");
    }

    if (pipe(pipe_err) < 0) {
        err(1, "pipe");
    }

    epoll_watch(pipe_out[0]);
    epoll_watch(pipe_err[0]);

    atexit(kill_group);

    int pid = syscall(__NR_clone,
                      SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET,
                      NULL);

    if (pid == 0) {
        close(0);
        dup2(pipe_out[1], 1);
        dup2(pipe_err[1], 2);

        close(pipe_out[0]);
        close(pipe_out[1]);
        close(pipe_err[0]);
        close(pipe_err[1]);

        init_cgroup();

        if (sethostname(hostname, strlen(hostname)) < 0) {
            err(1, "sethostname");
        }

        // avoid propagating mounts to the real root
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
            err(1, "mount /");
        }

        // turn directory into a bind mount
        if (mount(root, root, "bind", MS_BIND|MS_REC, NULL) < 0) {
            err(1, "bind mount");
        }

        // re-mount as read-only
        if (mount(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL) < 0) {
            err(1, "remount bind mount");
        }

        if (chroot(root) < 0) {
            err(1, "chroot");
        }

        if (chdir("/") < 0) {
            err(1, "chdir");
        }

        if (mount(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
            err(1, "mount /proc");
        }

        if (mount(NULL, "/tmp", "tmpfs", MS_NOSUID|MS_NODEV, NULL) < 0) {
            err(1, "mount /tmp");
        }

        struct passwd pw;
        size_t buffer_len = sysconf(_SC_GETPW_R_SIZE_MAX);
        char *buffer = (char *)malloc(buffer_len);
        if (!buffer) {
            err(1, NULL);
        }
        struct passwd *p_pw = &pw;
        getpwnam_r(username, &pw, buffer, buffer_len, &p_pw);
        if (!p_pw) {
            fprintf(stderr, "getpwnam_r failed to find requested entry.\n");
            return 1;
        }

        if (pw.pw_dir) {
            if (mount(NULL, pw.pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL) < 0) {
                err(1, "mount %s", pw.pw_dir);
            }
        }

        // create a new session
        if (setsid() < 0) {
            err(1, "setsid");
        }

        if (setgid(pw.pw_gid) < 0) {
            err(1, "setgid");
        }
        if (setuid(pw.pw_uid) < 0) {
            err(1, "setuid");
        }

        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
            return 1;
        }

        auto check = [](int rc) {
            if (rc < 0) {
                errx(1, "%s", strerror(-rc));
            }
        };

#define ALLOW(x) do { check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(x), 0)); } while (0)

        ALLOW(access);
        ALLOW(arch_prctl);
        ALLOW(brk);
        ALLOW(chdir);
        ALLOW(chmod);
        ALLOW(clone);
        ALLOW(close);
        ALLOW(dup);
        ALLOW(dup2);
        ALLOW(execve);
        ALLOW(exit);
        ALLOW(exit_group);
        ALLOW(faccessat);
        ALLOW(fadvise64);
        ALLOW(fcntl);
        ALLOW(fstat);
        ALLOW(futex);
        ALLOW(getcwd);
        ALLOW(getdents);
        ALLOW(getegid);
        ALLOW(geteuid);
        ALLOW(getgid);
        ALLOW(getpgrp);
        ALLOW(getpid);
        ALLOW(getppid);
        ALLOW(getrlimit);
        ALLOW(getrusage);
        ALLOW(getuid);
        ALLOW(ioctl);
        ALLOW(lseek);
        ALLOW(lstat);
        ALLOW(madvise);
        ALLOW(mmap);
        ALLOW(mprotect);
        ALLOW(mremap);
        ALLOW(munmap);
        ALLOW(nanosleep);
        ALLOW(open);
        ALLOW(openat);
        ALLOW(pipe);
        ALLOW(read);
        ALLOW(readlink);
        ALLOW(rt_sigaction);
        ALLOW(rt_sigprocmask);
        ALLOW(rt_sigreturn);
        ALLOW(setrlimit);
        ALLOW(set_robust_list);
        ALLOW(set_tid_address);
        ALLOW(stat);
        ALLOW(statfs);
        ALLOW(umask);
        ALLOW(uname);
        ALLOW(unlink);
        ALLOW(vfork);
        ALLOW(wait4);
        ALLOW(write);

#undef ALLOW

        check(seccomp_load(ctx));

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL};
        if (execve(argv[optind], argv + optind, env) < 0) {
            err(1, "execve");
        }
    } else if (pid < 0) {
        err(1, "clone");
    }

    if (timeout) {
        struct itimerspec spec = {
            .it_value.tv_sec = timeout
        };

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

                return si.ssi_status;
            } else if (evt->data.fd == pipe_out[0]) {
                copy_pipe_to(pipe_out[0], 1);
            } else if (evt->data.fd == pipe_err[0]) {
                copy_pipe_to(pipe_err[0], 2);
            }
        }
    }
}
