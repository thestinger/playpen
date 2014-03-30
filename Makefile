PREFIX = /usr/local

CC = clang
CFLAGS += -std=c99 -O2 -DVERSION=\"$(shell git describe)\" $(shell pkg-config --cflags gio-2.0)
LDLIBS = -lseccomp $(shell pkg-config --libs gio-2.0) -lsystemd
LDFLAGS += -Wl,--as-needed

ifeq ($(CC), clang)
	CFLAGS += -Weverything \
		  -Wno-documentation \
		  -Wno-shift-sign-overflow \
		  -Wno-padded \
		  -Wno-disabled-macro-expansion \
		  -Wno-pedantic
else
	CFLAGS += -Wall -Wextra
endif

playpen: playpen.c

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
