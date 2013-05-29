CXX = clang++
CXXFLAGS = -std=c++11 -O2 -Wmost
LDLIBS = -lseccomp
LDFLAGS = -Wl,--as-needed
SYSCALLS_HEADER ?= /usr/include/asm/unistd_64.h

all: playpen syscalls.h

playpen: playpen.cc

syscalls.h:
	python gentab.py $(SYSCALLS_HEADER) > syscalls.h
