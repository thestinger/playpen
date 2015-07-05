PREFIX = /usr/local

# use clang as the fallback instead of cc
CC = $(shell echo $${CC:-clang})
CFLAGS += -std=c11 -D_GNU_SOURCE -O2 \
	  -fPIE -fstack-protector-strong \
	  -DVERSION=\"$(shell git describe)\"
LDLIBS = -lseccomp -lsystemd
LDFLAGS += -pie -Wl,--as-needed,-z,relro,-z,now

ifeq ($(CC), clang)
	CFLAGS += -Weverything \
		  -Wno-padded \
		  -Wno-disabled-macro-expansion
else
	CFLAGS += -Wall -Wextra
endif

playpen: playpen.c

install: playpen
	install -Dm755 $< $(DESTDIR)$(PREFIX)/bin/$<
