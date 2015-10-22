/*
 * Copyright (c) 2007-2012, Vsevolod Stakhov
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer. Redistributions in binary form
 * must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with
 * the distribution. Neither the name of the author nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/******************************************************************************

	Clamav clamd client library

	Scanning file with tcp-based clamd servers. Library for general use.
	Thread-safe if compiled with _THREAD_SAFE defined.

	Warnings logged via syslog (must be opended).

	Random generator used (random() must be initialized before use, e.g.
	by srandomdev() call).

	Written by Maxim Dounin, mdounin@rambler-co.ru

	$Id$

 ******************************************************************************/

#include "config.h"

#include "cfg_file.h"
#include "rmilter.h"
#include "libclamc.h"

/* Maximum time in seconds during which clamav server is marked inactive after scan error */
#define INACTIVE_INTERVAL 60.0
/* Maximum number of failed attempts before marking server as inactive */
#define MAX_FAILED 5
/* Maximum inactive timeout (20 min) */
#define MAX_TIMEOUT 1200.0


/* Global mutexes */

#ifdef _THREAD_SAFE
pthread_mutex_t mx_clamav_write = PTHREAD_MUTEX_INITIALIZER;
#endif

/*****************************************************************************/

/*
 * poll_fd() - wait for some POLLIN event on socket for timeout milliseconds.
 */

static int 
poll_fd(int fd, int timeout, short events)
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

static int 
connect_t(int s, const struct sockaddr *name, socklen_t namelen, int timeout)
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
 * clamscan_socket() - send file to specified host. See clamscan() for
 * load-balanced wrapper.
 * 
 * returns 0 when checked, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int 
clamscan_socket(const char *file, const struct clamav_server *srv, char *strres, size_t strres_len, struct config_file *cfg)
{
	char *c;
#ifdef HAVE_PATH_MAX
	char path[PATH_MAX], buf[PATH_MAX + 10];
#elif defined(HAVE_MAXPATHLEN)
	char path[MAXPATHLEN], buf[MAXPATHLEN + 10];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	struct sockaddr_un server_un;
	struct sockaddr_in server_in, server_w;
	int s, sw, r, fd, port = 0, path_len, ofl;
	struct stat sb;

	*strres = '\0';

	/* somebody doesn't need reply... */
	if (!srv)
		return 0;

	if (srv->sock_type == AF_LOCAL) {
		if (!realpath(file, path)) {
			msg_warn("clamav: realpath: %s", strerror (errno));
			return -1;
		}
		/* unix socket, use 'SCAN <filename>' command on clamd */
		r = snprintf(buf, sizeof(buf), "SCAN %s\n", path);

		memset(&server_un, 0, sizeof(server_un));
		server_un.sun_family = AF_UNIX;
		strncpy(server_un.sun_path, srv->sock.unix_path, sizeof(server_un.sun_path));

		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			msg_warn("clamav: socket %s: %s", srv->sock.unix_path,
					strerror (errno));
			return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_un, sizeof(server_un), cfg->clamav_connect_timeout) < 0) {
			msg_warn("clamav: connect %s: %s", srv->sock.unix_path,
					strerror (errno));
			close(s);
			return -1;
		}
		if (write(s, buf, r) != r) {
			msg_warn("clamav: write %s: %s", srv->sock.unix_path,
					strerror (errno));
			close(s);
			return -1;
		}

	} else {
		/* inet hostname, send stream over tcp/ip */

		memset(&server_in, 0, sizeof(server_in));
		server_in.sin_family = AF_INET;
		server_in.sin_port = srv->sock.inet.port;
		memcpy((char *)&server_in.sin_addr, &srv->sock.inet.addr, sizeof(struct in_addr));

		if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
			msg_warn("clamav: socket: %s", strerror (errno));
			return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_in, sizeof(server_in), cfg->clamav_connect_timeout) < 0) {
			msg_warn("clamav: connect %s: %s", srv->name, strerror (errno));
			close(s);
			return -1;
		}

		snprintf(path, sizeof(path), "stream");
		r = snprintf(buf, sizeof(buf), "STREAM\n");

		if (write(s, buf, r) != r) {
			msg_warn("clamav: write %s: %s", srv->name, strerror (errno));
			close(s);
			return -1;
		}
		if (poll_fd(s, cfg->clamav_port_timeout, POLLIN) < 1) {
			msg_warn("clamav: timeout waiting port %s", srv->name);
			close(s);
			return -1;
		}

		/* clamav must reply with PORT to connect */

		buf[0] = 0;
		if ((r = read(s, buf, sizeof(buf))) > 0)
			buf[r] = 0;

		if (strncmp(buf, "PORT ", sizeof("PORT ") - 1) == 0) {
			port = atoi(buf + 5);
		}

		if (port < 1024) {
			msg_warn("clamav: can't get port number for data stream, got: %s", buf);
			close(s);
			return -1;
		}

		/*
		 * connect to clamd data socket
		 */
		if ((sw = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			msg_warn("clamav: socket (%s): %s", srv->name, strerror (errno));
			close(s);
			return -1;
		}

		memset(&server_w, 0, sizeof(server_w));
		server_w.sin_family = AF_INET;
		server_w.sin_port = htons(port);
		memcpy((char *)&server_w.sin_addr, (char *)&server_in.sin_addr, sizeof(struct in_addr));

		if (connect_t(sw, (struct sockaddr *) & server_w, sizeof(server_w), cfg->clamav_port_timeout) < 0) {
			msg_warn("clamav: connect data (%s): %s", srv->name,
					strerror (errno));
			close(sw);
			close(s);
			return -1;
		}

		/*
		 * send data stream
		 */

		fd = open(file, O_RDONLY);
		if (fstat (fd, &sb) == -1) {
			msg_warn ("clamav: stat failed: %s", strerror (errno));
			close(sw);
			close(s);
			return -1;
		}

		/* Set blocking again */
		ofl = fcntl(sw, F_GETFL, 0);
		fcntl(sw, F_SETFL, ofl & (~O_NONBLOCK));

#ifdef HAVE_SENDFILE
#ifdef FREEBSD
		if (sendfile(fd, sw, 0, 0, 0, 0, 0) != 0) {
			msg_warn("clamav: sendfile (%s): %s", srv->name, strerror (errno));
			close(sw);
			close(fd);
			close(s);
			return -1;
		}
#elif defined(LINUX)
		off_t off = 0;
		if (sendfile(sw, fd, &off, sb.st_size) == -1) {
			msg_warn("clamav: sendfile (%s): %s", srv->name, strerror (errno));
			close(sw);
			close(fd);
			close(s);
			return -1;		
		}
#endif
#else
		while ((r = read (fd, buf, sizeof(buf))) > 0) {
			write (sw, buf, r);
		}
#endif
		close(fd);
		close(sw);
	}

	/* wait for reply */

	if (poll_fd(s, cfg->clamav_results_timeout, POLLIN) < 1) {
		msg_warn("clamav: timeout waiting results %s", srv->name);
		close(s);
		return -1;
	}

	/*
	 * read results
	 */

	buf[0] = 0;

	while ((r = read(s, buf, sizeof(buf))) > 0) {
		buf[r] = 0;
	}

	if (r < 0) {
		msg_warn("clamav: read, %s: %s", srv->name, strerror (errno));
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
		msg_warn("clamav: error (%s) %s", srv->name, buf);
		return -1;
	}

	/*
	 * Most common reason is clamd died while processing our request. Try to
	 * save file for further investigation and fail.
	 */

	msg_warn("clamav: unexpected result on file (%s) %s, %s", srv->name, file, buf);
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

int 
clamscan(const char *file, struct config_file *cfg, char *strres, size_t strres_len)
{
	int retry = 5, r = -2;
	/* struct stat sb; */
	struct timeval t;
	double ts, tf;
	struct clamav_server *selected = NULL;

	*strres = '\0';
	/*
	 * Parse sockets to use in balancing.
	 */
	/* msg_warn("(clamscan) defined %d server sockets...", sockets_n); */

	/*
	 * save scanning start time
	 */
	gettimeofday(&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;

	/* try to scan with available servers */
	while (1) {
		if (cfg->weighted_clamav) {
			selected = (struct clamav_server *) get_upstream_master_slave ((void *)cfg->clamav_servers,
					cfg->clamav_servers_num, sizeof (struct clamav_server),
					t.tv_sec, cfg->clamav_error_time, cfg->clamav_dead_time,
					cfg->clamav_maxerrors);
		}
		else {
			selected = (struct clamav_server *) get_random_upstream ((void *)cfg->clamav_servers,
					cfg->clamav_servers_num, sizeof (struct clamav_server),
					t.tv_sec, cfg->clamav_error_time, cfg->clamav_dead_time,
					cfg->clamav_maxerrors);
		}
		if (selected == NULL) {
			msg_err ("clamscan: upstream get error, %s", file);
			return -1;
		}

		r = clamscan_socket (file, selected, strres, strres_len, cfg);
		if (r == 0) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("clamscan: unexpected problem, %s, %s", selected->name, file);
			break;
		}
		if (--retry < 1) {
			msg_warn("clamscan: retry limit exceeded, %s, %s", selected->name, file);
			break;
		}
		msg_warn("clamscan: failed to scan, retry, %s, %s", selected->name, file);
		sleep(1);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday(&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	if (*strres) {
		msg_info("clamscan: scan %f, %s, found %s, %s", tf - ts,
				selected->name,
				strres, file);
	}
	else {
		msg_info("clamscan: scan %f, %s, %s", tf -ts, 
				selected->name,
				file);
	}

	return r;
}

/* 
 * vi:ts=4 
 */
