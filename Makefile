PREFIX = /usr/local

# use clang as the fallback instead of cc
CC = $(shell echo $${CC:-clang})
CFLAGS += -std=c11 -O2 \
	  -fPIE -fstack-protector-strong \
	  -DVERSION=\"$(shell git describe)\" $(shell pkg-config --cflags gio-2.0)
LDLIBS = -lseccomp $(shell pkg-config --libs gio-2.0) -lsystemd
LDFLAGS += -pie -Wl,--as-needed,-z,relro,-z,now

ifeq ($(CC), clang)
	CFLAGS += -Weverything \
		  -Wno-documentation \
		  -Wno-shift-sign-overflow \
		  -Wno-padded \
		  -Wno-disabled-macro-expansion \
		  -Wno-assign-enum
else
	CFLAGS += -Wall -Wextra
endif

playpen: playpen.c

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
