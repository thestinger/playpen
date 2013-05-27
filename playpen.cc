#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <err.h>
#include <errno.h>
#include <linux/limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <seccomp.h>

static const char *const username = "rust";
static const char *const memory_limit = "128M";
static const char *const root = "sandbox";

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
        err(EXIT_FAILURE, "failed to create memory cgroup");
    }

    write_to("/sys/fs/cgroup/devices/playpen/tasks", "0");
    write_to("/sys/fs/cgroup/devices/playpen/devices.deny", "a");
    write_to("/sys/fs/cgroup/devices/playpen/devices.allow", "c 1:9 rw"); // urandom
}

int main(int argc, char **argv) {
    if (argc < 2) {
        errx(1, "need at least one argument");
    }

    int pid = syscall(__NR_clone,
                      SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET,
                      NULL);

    if (pid == 0) {
        init_cgroup();

        // avoid propagating mounts to the real root
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
            err(1, "mount");
        }

        // turn directory into a bind mount
        if (mount(root, root, "bind", MS_BIND|MS_REC, NULL) < 0) {
            err(1, "mount");
        }

        // re-mount as read-only
        if (mount(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL) < 0) {
            err(1, "mount");
        }

        if (chroot(root) < 0) {
            err(1, "chroot");
        }

        if (chdir("/") < 0) {
            err(1, "chdir");
        }

        if (mount(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
            err(1, "mount");
        }

        if (mount(NULL, "/tmp", "tmpfs", MS_NOSUID|MS_NODEV, NULL) < 0) {
            err(1, "mount");
        }

        if (mount(NULL, "/home/rust", "tmpfs", MS_NOSUID|MS_NODEV, NULL) < 0) {
            err(1, "mount");
        }

        // create a new session
        if (setsid() < 0) {
            err(1, "setsid");
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
        if (execve(argv[1], argv + 1, env) < 0) {
            err(1, "execve");
        }
    } else if (pid < 0) {
        err(1, "clone");
    }

    // TODO: timeout
    int stat;
    if (waitpid(pid, &stat, 0) != pid) {
        err(1, "waitpid");
    }

    if (WIFEXITED(stat)) {
        return WEXITSTATUS(stat);
    } else {
        raise(WTERMSIG(stat));
    }
}
