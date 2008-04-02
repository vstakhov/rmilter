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

#ifdef LINUX
#include <sys/sendfile.h>
#endif

#include "cfg_file.h"
#include "rmilter.h"
#include "libclamc.h"

/* Maximum time in seconds during which spamd server is marked inactive after scan error */
#define INACTIVE_INTERVAL 60.0
/* Maximum number of failed attempts before marking server as inactive */
#define MAX_FAILED 5
/* Maximum inactive timeout (20 min) */
#define MAX_TIMEOUT 1200.0


/* Global mutexes */

#ifdef _THREAD_SAFE
pthread_mutex_t mx_spamd_write = PTHREAD_MUTEX_INITIALIZER;
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
 * spamdscan_socket() - send file to specified host. See spamdscan() for
 * load-balanced wrapper.
 * 
 * returns 0 when spam not found, 1 when spam found, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int 
spamdscan_socket(const char *file, const struct spamd_server *srv, int spam_mark[2], struct config_file *cfg, char **symbols)
{
    char buf[MAXPATHLEN + 10], *c, *err;
    struct sockaddr_un server_un;
    struct sockaddr_in server_in;
    int s, r, fd, ofl;
	struct stat sb;

    /* somebody doesn't need reply... */
    if (!srv)
		return 0;

    if (srv->sock_type == AF_LOCAL) {

		memset(&server_un, 0, sizeof(server_un));
		server_un.sun_family = AF_UNIX;
		strncpy(server_un.sun_path, srv->sock.unix_path, sizeof(server_un.sun_path));

		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    	msg_warn("spamd: socket %s, %d: %m", srv->sock.unix_path, errno);
	    	return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_un, sizeof(server_un), cfg->spamd_connect_timeout) < 0) {
	    	msg_warn("spamd: connect %s, %d: %m", srv->sock.unix_path, errno);
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
	    	msg_warn("spamd: socket %d: %m",  errno);
	    	return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_in, sizeof(server_in), cfg->spamd_connect_timeout) < 0) {
	    	msg_warn("spamd: connect %s, %d: %m", srv->name, errno);
	    	close(s);
	    	return -1;
		}
	}
	/* Get file size */
	fd = open(file, O_RDONLY);
	if (fstat (fd, &sb) == -1) {
		msg_warn ("spamd: stat failed: %m");
	    close(s);
		return -1;
	}
	
	if (poll_fd(s, cfg->spamd_connect_timeout, POLLOUT) < 1) {
		msg_warn ("spamd: timeout waiting writing, %s", srv->name);
		close (s);
		return -1;
	}
	/* Set blocking again */
	ofl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, ofl & (~O_NONBLOCK));

	r = snprintf (buf, sizeof (buf), "SYMBOLS SPAMC/1.2\r\nContent-length: %ld\r\n\r\n", (long int)sb.st_size);
	write (s, buf, r);

#if defined(FREEBSD) || defined(HAVE_SENDFILE)
	if (sendfile(fd, s, 0, 0, 0, 0, 0) != 0) {
		msg_warn("spamd: sendfile (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;
	}
#elif defined(LINUX)
	off_t off = 0;
	if (sendfile(s, fd, &off, sb.st_size) == -1) {
		msg_warn("spamd: sendfile (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;		
	}
#else 
#error "sendfile required"
#endif

    fcntl(s, F_SETFL, ofl);
	close(fd);

    /* wait for reply */

    if (poll_fd(s, cfg->spamd_results_timeout, POLLIN) < 1) {
		msg_warn("spamd: timeout waiting results %s", srv->name);
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
		msg_warn("spamd: read, %s, %d: %m", srv->name, errno);
		close(s);
		return -1;
    }

    close(s);

    /*
     * ok, we got result; test what we got
     */

    if ((c = strstr(buf, "Spam: ")) == NULL) {
		msg_warn("spamd: unexpected result on file (%s) %s, %s", srv->name, file, buf);
		return -2;
	}
	else {
		/* Find mark */
		c = strchr (c, ';');
		if (c != NULL && *c != '\0') {
			spam_mark[0] = strtol (c + 1, &err, 10);
			if (*err == ' ' && *(err + 1) == '/') {
				spam_mark[1] = strtol (err + 3, NULL, 10);
			}
			else {
				spam_mark[1] = 0;
			}
		}
		else {
			spam_mark[0] = 0;
			spam_mark[1] = 0;
		}

		if (strstr(buf, "True") != NULL) {
			return 1;
		}
	}

	/* Skip empty lines */
	while (*c && *c++ != '\n');
	while (*c++ && (*c == '\r' || *c == '\n'));
	/* Write symbols */
	if (*c == '\0') {
		*symbols = NULL;
	}
	else {
		*symbols = strdup (c);
	}

	return 0;
}

/*
 * spamdscan() - send file to one of remote spamd, with pseudo load-balancing
 * (select one random server, fallback to others in case of errors).
 * 
 * returns 0 if file scanned and spam not found, 
 * 1 if file scanned and spam found , -1 when
 * retry limit exceeded, -2 on unexpected error, e.g. unexpected reply from
 * server (suppose scanned message killed spamd...)
 */

int 
spamdscan(const char *file, struct config_file *cfg, int spam_mark[2])
{
    int retry = 5, r = -2;
    struct timeval t;
    double ts, tf;
    struct spamd_server *selected = NULL;
	char *symbols = NULL;

    gettimeofday(&t, NULL);
    ts = t.tv_sec + t.tv_usec / 1000000.0;

    /* try to scan with available servers */
    while (1) {
		selected = (struct spamd_server *) get_random_upstream ((void *)cfg->spamd_servers,
											cfg->spamd_servers_num, sizeof (struct spamd_server),
											t.tv_sec, cfg->spamd_error_time, cfg->spamd_dead_time, cfg->spamd_maxerrors);
		if (selected == NULL) {
			msg_err ("spamdscan: upstream get error, %s", file);
			return -1;
		}

		r = spamdscan_socket (file, selected, spam_mark, cfg, &symbols);
		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
	    	break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
	    	msg_warn("spamdscan: unexpected problem, %s, %s", selected->name, file);
	    	break;
		}
		if (--retry < 1) {
	    	msg_warn("spamdscan: retry limit exceeded, %s, %s", selected->name, file);
	    	break;
		}
		msg_warn("spamdscan: failed to scan, retry, %s, %s", selected->name, file);
		sleep(1);
    }

    /*
     * print scanning time, server and result
     */
    gettimeofday(&t, NULL);
    tf = t.tv_sec + t.tv_usec / 1000000.0;

    if (r == 1) {
		msg_info("spamdscan: scan %f, %s, spam found [%d/%d], %s, %s", tf - ts,
					selected->name, 
					spam_mark[0], spam_mark[1],
					(symbols != NULL) ? symbols : "no symbols", file);
		if (symbols != NULL) {
			free (symbols);
		}
	}
    else {
		msg_info("spamdscan: scan %f, %s, [%d/%d], %s", tf -ts, 
					selected->name,
					spam_mark[0], spam_mark[1], file);
	}

    return r;
}

/* 
 * vi:ts=4 
 */
