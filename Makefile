# $Id$

DCC_VER=1.2.74

CFLAGS = -W -Wall -Wpointer-arith -Wno-unused-parameter \
		 -Wno-unused-function -Wunused-variable -Wno-sign-compare \
		 -Wunused-value -ggdb -I /usr/local/include \
		 -I./dcc-dccd-${DCC_VER}/include
LD_PATH = -L /usr/local/lib -L dcc-dccd-${DCC_VER}/dcclib
LIBS = -lmilter -lpcre -lspf2 -ldcc
PTHREAD_FLAGS = -D_THREAD_SAFE -pthread
CC ?= gcc
LEX ?= lex
YACC ?= yacc
EXEC=rmilter
LOCALBASE=/usr/local

YACC_SRC=cfg_file.y
LEX_SRC=cfg_file.l
YACC_OUTPUT=cfg_yacc.c
LEX_OUTPUT=cfg_lex.c

SOURCES=regexp.c spf.c rmilter.c libclamc.c ${LEX_OUTPUT} ${YACC_OUTPUT}
OBJECTS=${SOURCES:C/\.c/.o/g}

all: dcc lex build link

dcc: dcc-${DCC_VER}.tar.gz
	test -d dcc-dccd-${DCC_VER} || ( tar xzf dcc-${DCC_VER}.tar.gz && \
	cd dcc-dccd-${DCC_VER} && ./configure && make && \
	cd .. )

lex: ${LEX_SRC} ${YACC_SRC}
	${LEX} -o${LEX_OUTPUT} ${LEX_SRC}
	${YACC} -d -o ${YACC_OUTPUT} ${YACC_SRC}

build: ${SOURCES}
.for src in ${SOURCES}
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c ${src} 
.endfor

link: ${OBJECTS}
	${CC} ${PTHREAD_FLAGS} ${LD_PATH} ${OBJECTS} ${LIBS} -o ${EXEC}

# pw user add -n rmilter -u 3310 -c 'Rambler milter' -s /sbin/nologin -d /nonexistent
install:
	install -b ${EXEC} ${LOCALBASE}/sbin/${EXEC}
	install -v ${EXEC}.sh ${LOCALBASE}/etc/rc.d
	install -v -d -m 755 -o ${EXEC} -g postfix /var/run/rmilter
	install -v -d -m 700 -o ${EXEC} /spool3/var/clam-tmp

clean:
	rm -f *.o ${EXEC} *.core
	rm -f cfg_lex.c cfg_yacc.c cfg_yacc.h
	rm -fr dcc-dccd-${DCC_VER}
