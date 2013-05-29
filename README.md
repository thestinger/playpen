Playpen is a secure application sandbox implemented with namespaces, cgroups and seccomp.

By default, only the `execve` system call is permitted and other system calls must be explicitly
whitelisted. The application is spawned in clean namespaces, so it's unable to see or modify the
system's mount points, processes, network or hostname. The chroot uses a read-only root directory,
so no locking is required and multiple playpen instances can share the same root. Cgroups are used
to limit the available memory resources and reliably kill the application and any forked children
after a timeout.
