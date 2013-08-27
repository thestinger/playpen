PREFIX = /usr/local

CC = clang
CFLAGS += -std=c99 -O2 -Wmost -DVERSION=\"$(shell git describe)\"
LDLIBS = -lseccomp
LDFLAGS += -Wl,--as-needed

playpen: playpen.c

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
