/******************************************************************************

	Clamav clamd client library

	Scanning file with tcp-based clamd servers. Library for general use.
	Thread-safe if compiled with _THREAD_SAFE defined.

	Warnings logged via syslog (must be opended).

	Random generator used (random() must be initialized before use, e.g.
	by srandomdev() call).

	Written by Maxim Dounin, mdounin@rambler-co.ru

	$Id: libclamc.c,v 1.6 2007/03/12 19:34:06 citrin Exp $

******************************************************************************/

#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

/* config options here... bad, but works */
/*
#define SCAN_SIZELIMIT	1024 * 1024
*/

/* Logging in postfix style */

#define msg_warn(args...)	syslog(LOG_WARNING, ##args)
#define msg_info(args...)	syslog(LOG_INFO, ##args)

/* Global mutexes */

#ifdef _THREAD_SAFE
pthread_mutex_t mx_gethostbyname = PTHREAD_MUTEX_INITIALIZER;
#endif

/*****************************************************************************/

/*
 * poll_fd() - wait for some POLLIN event on socket for timeout milliseconds.
 */

int poll_fd(int fd, int timeout, short events)
{
    int r;
    struct pollfd fds[1];

    fds->fd = fd;
    fds->events = events;
    fds->revents = 0;
    while ((r = poll(fds, 1, timeout)) < 0) {
	if (errno != EINTR)
	    break;
    }
    return r;
}

/*
 * connect_t() - connect socket with timeout
 */

int connect_t(int s, const struct sockaddr *name, socklen_t namelen, int timeout)
{
    int r, ofl;
    int s_error = 0;
    socklen_t optlen;

    /* set nonblocking */
    ofl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, ofl | O_NONBLOCK);

    /* connect */
    r = connect(s, name, namelen);

    if (r < 0 && errno == EINPROGRESS) {
	/* wait for timeout */
	r = poll_fd(s, timeout, POLLOUT);
	if (r == 0) {
	    r = -1;
	    errno = ETIMEDOUT;
	} else if (r > 0) {
	    /* check errors on socket, e. g. ECONNREFUSED */
	    optlen = sizeof(s_error);
	    /* XXX - errors in getsockopt are not checked, but it rarely fail */
	    getsockopt(s, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
	    if (s_error) {
		r = -1;
		errno = s_error;
	    }
	}
    }

    /* set blocking back */
    fcntl(s, F_SETFL, ofl);

    /* return */
    return r;
}

/*
 * strsep_n() - count tokens in string.
 * 
 * strsep_get() - get token in specified position.
 */

int strsep_n(const char *str)
{
    char *buf = strdup(str);
    char *sp, *s;
    int n = 0;

    if (!buf)
	return 0;

    for (sp = buf; (s = strsep(&sp, ", \t")) != NULL;) {
	if (*s != '\0')
	    n++;
    }

    free(buf);
    return n;
}

char *strsep_get(const char *str, int pos)
{
    char *buf = strdup(str);
    char *sp, *s;
    int n = 0;

    if (!buf)
	return 0;

    for (sp = buf; (s = strsep(&sp, ", \t")) != NULL;) {
	if (*s != '\0' && n++ == pos)
	    break;
    }

    if (s)
	s = strdup(s);

    free(buf);
    return s;
}

/*
 * clamscan_socket() - send file to specified host. See clamscan() for
 * load-balanced wrapper.
 * 
 * returns 0 when checked, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

int clamscan_socket(const char *file, const char *sock, char *strres, size_t strres_len)
{
    char path[MAXPATHLEN], buf[MAXPATHLEN + 10], *c;
    struct sockaddr_un server_un;
    struct sockaddr_in server_in, server_w;
    struct hostent *he;
    int s, sw, r, fd, port = 0, path_len;

    *strres = '\0';

    /* somebody doesn't need reply... */
    if (!sock || sock[0] == '\0')
	return 0;

    if (sock[0] == '/') {
	/* unix socket, use 'SCAN <filename>' command on clamd */

	if (!realpath(file, path)) {
	    msg_warn("clamav: realpath, %d: %m", errno);
	    return -1;
	}
	memset(&server_un, 0, sizeof(server_un));
	server_un.sun_family = AF_UNIX;
	strncpy(server_un.sun_path, sock, sizeof(server_un.sun_path));

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    msg_warn("clamav: socket %s, %d: %m", sock, errno);
	    return -1;
	}
	if (connect_t(s, (struct sockaddr *) & server_un, sizeof(server_un), 1000) < 0) {
	    msg_warn("clamav: connect %s, %d: %m", sock, errno);
	    close(s);
	    return -1;
	}
	if (write(s, buf, strlen(buf)) != strlen(buf)) {
	    msg_warn("clamav: write %s, %d: %m", sock, errno);
	    close(s);
	    return -1;
	}
    } else {
	/* inet hostname, send stream over tcp/ip */

#ifdef _THREAD_SAFE
	/* lock mutex, gethostbyname() isn't threadsafe */
	pthread_mutex_lock(&mx_gethostbyname);
#endif
	he = gethostbyname(sock);
	if (he == NULL) {
	    msg_warn("clamav: gethostbyname %s, %d: %s", sock, h_errno, hstrerror(h_errno));
#ifdef _THREAD_SAFE
	    pthread_mutex_unlock(&mx_gethostbyname);
#endif
	    close(s);
	    return -1;
	}
	memset(&server_in, 0, sizeof(server_in));
	server_in.sin_family = AF_INET;
	server_in.sin_port = htons(3310);
	memcpy((char *)&server_in.sin_addr, he->h_addr, sizeof(struct in_addr));

#ifdef _THREAD_SAFE
	pthread_mutex_unlock(&mx_gethostbyname);
#endif

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    msg_warn("clamav: socket %s, %d: %m", sock, errno);
	    return -1;
	}
	if (connect_t(s, (struct sockaddr *) & server_in, sizeof(server_in), 1000) < 0) {
	    msg_warn("clamav: connect %s, %d: %m", sock, errno);
	    close(s);
	    return -1;
	}
	snprintf(path, MAXPATHLEN, "stream");
	snprintf(buf, MAXPATHLEN, "STREAM");
	if (write(s, buf, strlen(buf)) != strlen(buf)) {
	    msg_warn("clamav: write %s, %d: %m", sock, errno);
	    close(s);
	    return -1;
	}
	if (poll_fd(s, 5000, POLLIN) < 1) {
	    msg_warn("clamav: timeout waiting port, %s", sock);
	    close(s);
	    return -1;
	}

	/* clamav must reply with PORT to connect */

	buf[0] = 0;
	if ((r = read(s, buf, MAXPATHLEN)) > 0)
	    buf[r] = 0;

	if (strncmp(buf, "PORT ", 5) == 0)
	    port = atoi(buf + 5);
	if (port < 1024) {
	    msg_warn("clamav: can't get port number for data stream, got: %s", buf);
	    close(s);
	    return -1;
	}

	/*
	 * connect to clamd data socket
	 */
	if ((sw = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    msg_warn("clamav: socket, %d: %m", errno);
	    close(s);
	    return -1;
	}
	memset(&server_w, 0, sizeof(server_w));
	server_w.sin_family = AF_INET;
	server_w.sin_port = htons(port);
	memcpy((char *)&server_w.sin_addr, (char *)&server_in.sin_addr, sizeof(struct in_addr));

	if (connect_t(sw, (struct sockaddr *) & server_w, sizeof(server_w), 15000) < 0) {
	    msg_warn("clamav: connect data, %d: %m", errno);
	    close(sw);
	    close(s);
	    return -1;
	}

	/*
	 * send data stream
	 */

	fd = open(file, O_RDONLY);
	if (sendfile(fd, sw, 0, 0, 0, 0, 0) != 0) {
	    msg_warn("clamav: sendfile, %d: %m", errno);
	    close(fd);
	    close(sw);
	    close(s);
	    return -1;
	}
	close(fd);
	shutdown(sw, SHUT_RDWR);
	close(sw);

    }

    /* wait for reply, timeout in 15 seconds */

    if (poll_fd(s, 15000, POLLIN) < 1) {
	msg_warn("clamav: timeout waiting results, %s", sock);
	close(s);
	return -1;
    }

    /*
     * read results
     */

    buf[0] = 0;
    while ((r = read(s, buf, MAXPATHLEN)) > 0) {
	buf[r] = 0;
    }

    if (r < 0) {
	msg_warn("clamav: read, %d: %m", errno);
	close(s);
	return -1;
    }
    close(s);

    /*
     * ok, we got result; test what we got
     */

    /* msg_warn("clamav: %s", buf); */
    if ((c = strstr(buf, "OK\n")) != NULL) {
	/* <file> ": OK\n" */
		return 0;

    } else if ((c = strstr(buf, "FOUND\n")) != NULL) {
	/* <file> ": " <virusname> " FOUND\n" */

		path_len = strlen(path);
		if (strncmp(buf, path, path_len) != 0) {
	    	msg_warn("clamav: paths differ: '%s' instead of '%s'", buf, path);
	    	return -1;
		}
		*(--c) = 0;
		c = buf + path_len + 2;

	   /*
	 	* Virus found, store in state to further checks with
	 	* smtpd_dot_restrictions = check_clamd_access pcre:/db/maps/clamd
	 	* (in postfix).
	 	*/

		/* msg_warn("clamav: found %s", c); */
		snprintf(strres, strres_len, "%s", c);
		return 0;

    } else if ((c = strstr(buf, "ERROR\n")) != NULL) {
		*(--c) = 0;
		msg_warn("clamav: error %s", buf);
		return -1;
    }

    /*
     * Most common reason is clamd died while processing our request. Try to
     * save file for further investigation and fail.
     */

    msg_warn("clamav: unexpected result on file %s, %s", file, buf);
    return -2;
}

/*
 * clamscan() - send file to one of remote clamd, with pseudo load-balancing
 * (select one random server, fallback to others in case of errors).
 * 
 * returns 0 if file scanned (or not scanned due to filesize limit), -1 when
 * retry limit exceeded, -2 on unexpected error, e.g. unexpected reply from
 * server (suppose scanned message killed clamd...)
 */

int clamscan(const char *file, const char *sockets, char *strres, size_t strres_len)
{
    int retry = 5, r = -2;
    /* struct stat sb; */
    struct timeval t;
    double ts, tf;
    char *sock = NULL;
    int sockets_n = 0;

    *strres = '\0';
    /* syslog(LOG_WARNING, "(clamscan) %s", file); */

    /* check file size */
/*
    stat(file, &sb);
    if (sb.st_size > SCAN_SIZELIMIT) {
	msg_warn("(clamscan) message size exceeds limit, not scanned, %s", file);
	return 0;
    }
*/

    /*
     * Parse sockets to use in balancing.
     */

    sockets_n = strsep_n(sockets);
    /* msg_warn("(clamscan) defined %d server sockets...", sockets_n); */

    /*
     * save scanning start time
     */
    gettimeofday(&t, NULL);
    ts = t.tv_sec + t.tv_usec / 1000000.0;

    /* try to scan with available servers */
    while (1) {
	if (sock) {
	    free(sock);
	    sock = NULL;
	}
	sock = strsep_get(sockets, random() % sockets_n);
	/* msg_warn("(clamscan) using socket %s", sock); */
	r = clamscan_socket(file, sock, strres, strres_len);
	if (r == 0) {
	    break;
	}
	if (r == -2) {
	    msg_warn("(clamscan) unexpected problem, %s", file);
	    break;
	}
	if (--retry < 1) {
	    msg_warn("(clamscan) retry limit exceeded, %s", file);
	    break;
	}
	msg_warn("(clamscan) failed to scan, retry, %s, %s", sock, file);
	sleep(1);
    }

    /*
     * print scanning time, server and result
     */
    gettimeofday(&t, NULL);
    tf = t.tv_sec + t.tv_usec / 1000000.0;

    if (*strres)
	msg_info("(clamscan) scan %f, %s, %s, found %s", tf - ts, sock, file, strres);
    else
	msg_info("(clamscan) scan %f, %s, %s", tf - ts, sock, file);
    free(sock);

    return r;
}

/*****************************************************************************/

#if 0

int main(int argc, char *argv[])
{
    int c, r;
    const char *args = "d:";
    char *var_clamd_socket = NULL;
    char strres[MAXPATHLEN];

    openlog("rmilter-clam", LOG_PID | LOG_PERROR, LOG_MAIL);

    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1) {
	switch (c) {
	case 'd':
	    var_clamd_socket = strdup(optarg);
	    break;
	}
    }

    if (!var_clamd_socket || *var_clamd_socket == '\0') {
	msg_warn("clamd servers not set");
	exit(EX_USAGE);
    }
    if (argc <= optind) {
	msg_warn("no file to scan");
	exit(EX_USAGE);
    }
    srandomdev();

    msg_warn("scanning %s", argv[optind]);
    clamscan(argv[optind], var_clamd_socket, strres, MAXPATHLEN);
    msg_warn("result is '%s'", strres);

    if (var_clamd_socket) {
	free(var_clamd_socket);
	var_clamd_socket = NULL;
    }
    return r;
}

#endif				/* 0 */

/* eof */
