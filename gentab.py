import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: %s path_to_header\n" % sys.argv[0])
    sys.exit(1)

syscalls = []

with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith("#define __NR_"):
            syscalls.append(line.strip().replace("#define __NR_", "").split(" "))

print("""
struct syscall_pair {
    const char *key;
    const unsigned int val;
};

static const unsigned int num_syscalls = %d;
struct syscall_pair kvs[%d] = {""" % (len(syscalls), len(syscalls)))

for syscall in sorted(syscalls, key=lambda v: v[0]):
    print("{.key=\"%s\", .val=%s}," % (syscall[0], syscall[1]))

print("};")
