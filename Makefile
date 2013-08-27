PREFIX = /usr/local

CXX = clang++
CXXFLAGS += -std=c++11 -O2 -Wmost -DVERSION=\"$(shell git describe)\"
LDLIBS = -lseccomp
LDFLAGS += -Wl,--as-needed
SYSCALLS_HEADER ?= /usr/include/asm/unistd_64.h

playpen: playpen.cc

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
