# $Id$

DCC_VER=1.2.74
LOCALBASE?=/usr/local

VERSION = 1.4

CFLAGS += -W -Wall -Wpointer-arith -Wno-unused-parameter \
		 -Wno-unused-function -Wunused-variable -Wno-sign-compare \
		 -Wunused-value -ggdb -I${LOCALBASE}/include \
		 -I./dcc-dccd-${DCC_VER}/include -DMVERSION=\"${VERSION}\"
LD_PATH += -L${LOCALBASE}/lib  -Ldcc-dccd-${DCC_VER}/dcclib
LIBS += -lmilter -lpcre -lspf2 -ldcc -lm
PTHREAD_FLAGS = -D_THREAD_SAFE -pthread
CC ?= gcc
LEX ?= lex
YACC ?= yacc
EXEC=rmilter
PREFIX?=/usr/local

YACC_SRC=cfg_file.y
LEX_SRC=cfg_file.l
YACC_OUTPUT=cfg_yacc.c
LEX_OUTPUT=cfg_lex.c

SOURCES=upstream.c regexp.c spf.c rmilter.c libclamc.c cfg_file.c ratelimit.c memcached.c ${LEX_OUTPUT} ${YACC_OUTPUT}
OBJECTS=${SOURCES:C/\.c/.o/g}

all: dcc lex build link

dcc: dcc-${DCC_VER}.tar.gz
	test -d dcc-dccd-${DCC_VER} || ( tar xzf dcc-${DCC_VER}.tar.gz && \
	cd dcc-dccd-${DCC_VER} && ./configure && make && \
	cd .. )

lex: ${LEX_SRC} ${YACC_SRC}
	${LEX} -o${LEX_OUTPUT} ${LEX_SRC}
	${YACC} -d -o ${YACC_OUTPUT} ${YACC_SRC}

build: 
	@for src in ${SOURCES} ; do \
	echo ${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c $$src ; \
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c $$src  || exit ; \
	done

link:
	${CC} ${PTHREAD_FLAGS} ${LD_PATH} ${OBJECTS} ${LIBS} -o ${EXEC}

memctest: upstream.c memcached.c memcached-test.c
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c upstream.c
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c memcached.c
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c memcached-test.c
	${CC} ${PTHREAD_FLAGS} ${LD_PATH} upstream.o memcached.o memcached-test.o ${LIBS} -o memcached-test

install:
	install -b ${EXEC} ${PREFIX}/sbin/${EXEC}
	install -v ${EXEC}.sh ${PREFIX}/etc/rc.d

clean:
	rm -f *.o ${EXEC} *.core
	rm -f cfg_lex.c cfg_yacc.c cfg_yacc.h
	rm -fr dcc-dccd-${DCC_VER}
