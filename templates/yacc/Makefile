YFLAGS=
CFLAGS+=	-O2 -Wall -Wextra

all: parse

clean:
	rm -f parse{.c,.o,}

parse: parse.o
	${LINK} parse.o ${LDLIBS} -o $@


CC?=		cc
YACC?=		yacc
COMPILE=	${CC} ${CPPFLAGS} ${CFLAGS} -c
LINK=		${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS}

.SUFFIXES: .y .c .o

.c.o:
	${COMPILE} $<

.y.c:
	${YACC} ${YFLAGS} $<
	mv y.tab.c $@

.PHONY: all clean
