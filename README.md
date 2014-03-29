Playpen is a secure application sandbox built with modern Linux sandboxing features.

# Features

* The sandboxed application is spawned inside a systemd scope unit, providing
  integration with systemd tools like `systemd-cgtop`.
* The application is contained inside a read-only root directory with `chroot`.
  A private mount namespace allows for any number of playpen instances to share the
  same root concurrently while still having a writable in-memory /tmp, /dev/shm
  and home directory.
* System call whitelisting forbids all but the `execve` call by default.
* Device whitelisting prevents reading, writing or creating any devices by default.
* The initial process and any forked children can be reliably killed.
* An optional timeout can take care of automatically killing the contained processes.
* A process namespace hides all external processes from the sandbox.
* A network namespace provides a private loopback and no external interfaces.
* The system's hostname and IPC resources are hidden from the sandbox.

# Dependencies

* Linux 3.8 or later
* [libseccomp](http://sourceforge.net/projects/libseccomp/) 2.1.1 or later
* systemd
