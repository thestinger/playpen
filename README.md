Playpen is a secure application sandbox built with modern Linux sandboxing features.

# Features

* The sandboxed application is spawned inside a systemd scope unit, providing
  integration with systemd tools like `systemd-cgtop` and robust control group
  management.
* The application is contained inside a read-only root directory with `chroot`.
* System call whitelisting forbids all but the `execve` call by default and
  includes support for parameter constraints. A learning mode is available to
  automatically generate a minimal whitelist based on the system calls and
  parameters used by the sandboxed process.
* A mount namespace is leveraged to provide writable /tmp, /dev/tmp and home
  directories as in-memory (tmpfs) filesystems. Since these mounts are private,
  any number of Playpen instances can share the same root.
* The memory of all contained processes is limited via the scope unit's memory
  control group. The memory control group will include usage of the private
  tmpfs mounts towards the total.
* The number of tasks is limited via the scope unit's pids control group in
  addition to the indirect limitation via the memory control group.
* Device whitelisting prevents reading, writing or creating any devices by default.
* The initial process and any forked children can be reliably killed.
* An optional timeout can take care of automatically killing the contained processes.
* A process namespace hides all external processes from the sandbox.
* A network namespace provides a private loopback and no external interfaces.
* The system's hostname and IPC resources are hidden from the sandbox via
  namespaces.

# System call whitelisting

A system call will only be permitted by the kernel if it matches one or more of
the provided rules. Rules can be supplied either via a file (-S) or by passing
rules on the command-line (-s).

Learning mode (-l) will append any missing rules to the whitelist file. It will
add constraints on parameters specifying a sub-command, such as the request
argument to ioctl. A coarser learning mode without parameter constraints is
available (-L).

Syntax for the whitelist:

    system_call
    system_call: parameter operator value
    system_call: parameter operator value, parameter operator value, [...]

Tabs and spaces are ignored. The command-line syntax uses semicolons as the
separator between rules rather than expecting one rule per line.

The valid operators are !=, <, <=, >, >= and ==.

For example:

    bar
    foo: 2 == 100
    foo: 2 == 200, 1 != 300, 1 != 400, 3 < 500

This permits the `bar` system call in all cases. The `foo` system call is
permitted if either:

* the second parameter is equal to 100
* the second parameter is equal to 200, the first parameter is not equal to
  either 300 or 400 and the third parameter is less than 500

# Example

    # create a chroot
    mkdir sandbox
    pacstrap -cd sandbox

    # run `ls -l` in the sandbox and create a system call whitelist
    playpen sandbox -S whitelist -l -- ls -l /

    # run it again, enforcing the learned system call whitelist
    playpen sandbox -S whitelist -- ls -l /

# Dependencies

* Linux 3.8 or later
* [libseccomp](https://github.com/seccomp/libseccomp) 2.1.1 or later
* systemd
