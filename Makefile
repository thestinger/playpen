CXX = clang++
CXXFLAGS = -std=c++11 -O2 -Wmost
LDLIBS = -lseccomp
LDFLAGS = -Wl,--as-needed
SYSCALLS_HEADER ?= /usr/include/asm/unistd_64.h

playpen: playpen.cc syscalls.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

syscalls.h: gentab.py
	python gentab.py $(SYSCALLS_HEADER) > syscalls.h
