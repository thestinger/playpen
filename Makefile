PREFIX = /usr/local

CXX = clang++
CXXFLAGS += -std=c++11 -O2 -Wmost
LDLIBS = -lseccomp
LDFLAGS += -Wl,--as-needed
SYSCALLS_HEADER ?= /usr/include/asm/unistd_64.h

playpen: playpen.cc syscalls.inc
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@ -DVERSION=\"$(shell git describe)\"

syscalls.inc: gentab.py
	python $< $(SYSCALLS_HEADER) > $@

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
