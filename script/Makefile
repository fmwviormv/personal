.POSIX:
ALL= con realpath tcpoversocks
CFLAGS+= -Wall -Wextra -Werror
#CFLAGS+= -DUSE_EVENT2
CFLAGS+= -DUSE_ACCEPT4
CFLAGS+= -DUSE_PLEDGE

all: $(ALL)

clean:
	rm -f $(ALL)

con: con.c
	$(CC) $(CFLAGS) -lutil -o $@ con.c

realpath: realpath.c
	$(CC) $(CFLAGS) -lutil -o $@ realpath.c

tcpoversocks: tcpoversocks.c
	$(CC) $(CFLAGS) -levent -o $@ tcpoversocks.c

.PHONY: all clean
