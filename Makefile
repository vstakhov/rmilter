# $Id$

CFLAGS = -W -Wall -Wpointer-arith -Wno-unused-parameter \
		 -Wno-unused-function -Wunused-variable -Wno-sign-compare \
		 -Wunused-value -Werror -ggdb -I /usr/local/include
LIBS = -L /usr/local/lib -lmilter
PTHREAD_FLAGS = -D_THREAD_SAFE -pthread
CC ?= gcc
SOURCES=rmilter.c libclamc.c
OBJECTS=${SOURCES:C/\.c/.o/g}
EXEC=rmilter
LOCALBASE=/usr/local

all: build link

build: ${SOURCES}
.for src in ${SOURCES}
	${CC} ${CFLAGS} ${PTHREAD_FLAGS} -c ${src} 
.endfor

link: ${OBJECTS}
	${CC} ${PTHREAD_FLAGS} ${LIBS} ${OBJECTS} -o ${EXEC}

# pw user add -n rmilter -u 3310 -c 'Rambler milter' -s /sbin/nologin -d /nonexistent
install:
	install -b ${EXEC} ${LOCALBASE}/sbin/${EXEC}
	install -v ${EXEC}.sh ${LOCALBASE}/etc/rc.d
	install -v -d -m 755 -o ${EXEC} -g postfix /var/run/rmilter
	install -v -d -m 700 -o ${EXEC} /spool3/var/clam-tmp

clean:
	rm -f *.o ${EXEC} *.core
