#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_PATH_MAX
#include <limits.h>
#endif
#ifdef HAVE_MAXPATHLEN
#include <sys/param.h>
#endif
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
#include "libspamd.h"

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

/* Rspamd protocol parsing regexps */
static pcre* re_metric = NULL;
static pcre* re_symbol = NULL;
static pcre* re_url = NULL;
static const char* sym_metric = "^Metric: ([^;]+); (True|False); (\\d+\\.?\\d*) / (\\d+\\.?\\d*)$";
static const char* sym_symbol = "^Symbol: ([^;]+); ((\\S+),)*(\\S+)?$";
static const char* sym_url = "^Urls: (([^,]+),)*([^,]+)?$";
static int re_initialized = 0;

/*****************************************************************************/

static void
prepare_proto_re ()
{
	int err;
	const char *err_str;
	/* May be race here */
	if (!re_initialized) {
		pthread_mutex_lock (&mx_spamd_write);
		if (!re_initialized) {
			re_metric = pcre_compile (sym_metric, 0, &err_str, &err, NULL);
			re_symbol = pcre_compile (sym_symbol, 0, &err_str, &err, NULL);
			re_url = pcre_compile (sym_url, 0, &err_str, &err, NULL);
			re_initialized = 1;
		}
		pthread_mutex_unlock (&mx_spamd_write);
	}
	
}

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
 * rspamdscan_socket() - send file to specified host. See spamdscan() for
 * load-balanced wrapper.
 * 
 * returns 0 when spam not found, 1 when spam found, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int 
rspamdscan_socket(SMFICTX *ctx, struct mlfi_priv *priv, const struct spamd_server *srv, 
					double spam_mark[2], struct config_file *cfg, char **symbols)
{
#ifdef HAVE_PATH_MAX
	char buf[PATH_MAX + 10], headerbuf[PATH_MAX + 10];
#elif defined(HAVE_MAXPATHLEN)
	char buf[MAXPATHLEN + 10], headerbuf[MAXPATHLEN + 10];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	char headername[40], tmpbuf[40];
	char *c, *str = NULL, *tok_ptr;
	struct sockaddr_un server_un;
	struct sockaddr_in server_in;
	int s, r, fd, ofl, selected_metric, do_token = 1, size = 0;
	struct stat sb;
	double metric_mark[2];
	int ovector[30];

	/* somebody doesn't need reply... */
	if (!srv)
		return 0;
	
	/* compile pcre if needed */
	prepare_proto_re ();

	if (srv->sock_type == AF_LOCAL) {

		memset(&server_un, 0, sizeof(server_un));
		server_un.sun_family = AF_UNIX;
		strncpy(server_un.sun_path, srv->sock.unix_path, sizeof(server_un.sun_path));

		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			msg_warn("rspamd: socket %s, %d: %m", srv->sock.unix_path, errno);
			return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_un, sizeof(server_un), cfg->spamd_connect_timeout) < 0) {
			msg_warn("rspamd: connect %s, %d: %m", srv->sock.unix_path, errno);
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
			msg_warn("rspamd: socket %d: %m",  errno);
			return -1;
		}
		if (connect_t(s, (struct sockaddr *) & server_in, sizeof(server_in), cfg->spamd_connect_timeout) < 0) {
			msg_warn("rspamd: connect %s, %d: %m", srv->name, errno);
			close(s);
			return -1;
		}
	}
	/* Get file size */
	fd = open(priv->file, O_RDONLY);
	if (fstat (fd, &sb) == -1) {
		msg_warn ("rspamd: stat failed: %m");
		close(s);
		return -1;
	}
	
	if (poll_fd(s, cfg->spamd_connect_timeout, POLLOUT) < 1) {
		msg_warn ("rspamd: timeout waiting writing, %s", srv->name);
		close (s);
		return -1;
	}
	/* Set blocking again */
	ofl = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, ofl & (~O_NONBLOCK));

	r = snprintf (buf, sizeof (buf), "SYMBOLS RSPAMC/1.1\r\nContent-length: %ld\r\n", (long int)sb.st_size);
	if (write (s, buf, r) == -1) {
		msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;
	}
	if (priv->priv_rcpt[0] != '\0') {
		r = snprintf (buf, sizeof (buf), "Rcpt: %s\r\n", priv->priv_rcpt);
		if (write (s, buf, r) == -1) {
			msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
			close(fd);
			close(s);
			return -1;
		}
	}
	if (priv->priv_from[0] != '\0') {
		r = snprintf (buf, sizeof (buf), "From: %s\r\n", priv->priv_from);
		if (write (s, buf, r) == -1) {
			msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
			close(fd);
			close(s);
			return -1;
		}
	}
	if (priv->priv_helo[0] != '\0') {
		r = snprintf (buf, sizeof (buf), "Helo: %s\r\n", priv->priv_helo);
		if (write (s, buf, r) == -1) {
			msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
			close(fd);
			close(s);
			return -1;
		}
	}
	if (priv->priv_ip[0] != '\0') {
		r = snprintf (buf, sizeof (buf), "IP: %s\r\n", priv->priv_ip);
		if (write (s, buf, r) == -1) {
			msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
			close(fd);
			close(s);
			return -1;
		}
	}

	if (write (s, "\r\n", 2) == -1) {
		msg_warn("rspamd: write (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;
	}

#if defined(FREEBSD) || defined(HAVE_SENDFILE)
	if (sendfile(fd, s, 0, 0, 0, 0, 0) != 0) {
		msg_warn("rspamd: sendfile (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;
	}
#elif defined(LINUX)
	off_t off = 0;
	if (sendfile(s, fd, &off, sb.st_size) == -1) {
		msg_warn("rspamd: sendfile (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;		
	}
#else 
	while ((r = read (fd, buf, sizeof (buf))) > 0) {
		write (s, buf, r);
	}
#endif

	fcntl(s, F_SETFL, ofl);
	close(fd);

	/* wait for reply */

	if (poll_fd(s, cfg->spamd_results_timeout, POLLIN) < 1) {
		msg_warn("rspamd: timeout waiting results %s", srv->name);
		close(s);
		return -1;
	}
	
	/*
	 * read results
	 */

	buf[0] = 0;
	*symbols = NULL;

	while ((r = read(s, buf, sizeof (buf))) > 0) {
		buf[r] = 0;
	}

	if (r < 0) {
		msg_warn("rspamd: read, %s, %d: %m", srv->name, errno);
		close(s);
		return -1;
	}

	close(s);
	
	/* Find metrics */
	tok_ptr = buf;

	while (tok_ptr) { 
		if (do_token) {
			str = strsep (&tok_ptr, "\r\n");
			size = strlen (str);
		}
		do_token = 1;
		if (size == 0) {
			/* Skip empty tokens */
			continue;
		}
		if ((r = pcre_exec (re_metric, NULL, str, size, 0, 0, ovector, sizeof (ovector) / sizeof (ovector[0]))) >= 0) {
			/* In matched pattern we have metric name in $1, spam flag in $2 and marks in $3 and $4 */
			/* Get metric name */
			c = str + ovector[2];
			s = ovector[3] - ovector[2];
			if (s >= sizeof (headername)) {
				msg_warn ("rspamd: metric name is too long: %d", s);
				return -1;
			}
			memcpy (tmpbuf, c, s);
			tmpbuf[s] = '\0';
			if (strcmp (tmpbuf, cfg->rspamd_metric) == 0) {
				selected_metric = 1;
			}
			else {
				selected_metric = 0;
			}
			/* Metric name in tmpbuf, now process marks */
			c = str + ovector[6];
			if (selected_metric) {
				spam_mark[0] = strtod (c, NULL);
			}
			else {
				metric_mark[0] = strtod (c, NULL);
			}
			c = str + ovector[8];
			if (selected_metric) {
				spam_mark[1] = strtod (c, NULL);
			}
			else {
				metric_mark[1] = strtod (c, NULL);
			}
			/* Now form header for this metric */
			if (!selected_metric) {
				snprintf (headername, sizeof (headername), "X-Rspamd-%s", tmpbuf);
				snprintf (headerbuf, sizeof (headerbuf), "%s ; %.2f / %.2f", 
							(metric_mark[0] > metric_mark[1]) ? "Spam" : "Ham",
							metric_mark[0], metric_mark[1]);
				smfi_addheader (ctx, headername, headerbuf);
			}
			/* Now try to extract all symbols */
			ofl = 0;
			while (tok_ptr) {
				str = strsep (&tok_ptr, "\r\n");
				size = strlen (str);
				if (size == 0) {
					/* Skip empty tokens */
					continue;
				}
				r = pcre_exec (re_symbol, NULL, str, size, 0, 0, ovector, sizeof (ovector) / sizeof (ovector[0]));
				if (r < 0) {
					headerbuf[ofl - 1] = '\0';
					/* Break on first non-symbol line, but save it for future use */
					do_token = 0;
					break;
				}
				/* In this match $1 is symbol name and $2... are symbol strings */
				/* At this moment we only extract symbol name */
				c = str + ovector[2];
				s = ovector[3] - ovector[2];
				if (s >= sizeof (tmpbuf)) {
					msg_warn ("rspamd: symbol name is too long: %d", s);
					return -1;
				}
				memcpy (tmpbuf, c, s);
				tmpbuf[s] = '\0';
				ofl += snprintf (headerbuf + ofl, sizeof (headerbuf) - ofl, "%s,", tmpbuf);
			}
			if (!selected_metric) {
				s = strlen (headername);
				snprintf (headername + s, sizeof (headername) - s, "-Symbols");
				smfi_addheader (ctx, headername, headerbuf);
			}
			else {
				*symbols = strdup (headerbuf);
			}
		}
	}
		
	if (spam_mark[0] > spam_mark[1]) {
		return 1;
	}

	return 0;
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
spamdscan_socket(const char *file, const struct spamd_server *srv, double spam_mark[2], struct config_file *cfg, char **symbols)
{
#ifdef HAVE_PATH_MAX
	char buf[PATH_MAX + 10];
#elif defined(HAVE_MAXPATHLEN)
	char buf[MAXPATHLEN + 10];
#else
#error "neither PATH_MAX nor MAXPATHEN defined"
#endif
	char *c, *err;
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
	if (write (s, buf, r) == -1) {
		msg_warn("spamd: write (%s), %d: %m", srv->name, errno);
		close(fd);
		close(s);
		return -1;
	}

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
	while ((r = read (fd, buf, sizeof (buf))) > 0) {
		write (s, buf, r);
	}
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

	while ((r = read(s, buf, sizeof (buf))) > 0) {
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
			spam_mark[0] = strtod (c + 1, &err);
			if (*err == ' ' && *(err + 1) == '/') {
				spam_mark[1] = strtod (err + 3, NULL);
			}
			else {
				spam_mark[1] = 0;
			}
		}
		else {
			spam_mark[0] = 0;
			spam_mark[1] = 0;
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
		err = strchr (c, '\r');
		if (err != NULL) {
			*err = '\0';
		}
		*symbols = strdup (c);
	}

	if (strstr(buf, "True") != NULL) {
			return 1;
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
spamdscan(SMFICTX *ctx, struct mlfi_priv *priv, struct config_file *cfg, double spam_mark[2])
{
	int retry = 5, r = -2, r1;
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
			msg_err ("spamdscan: upstream get error, %s", priv->file);
			return -1;
		}
		
		if (selected->type == SPAMD_SPAMASSASSIN) {
			r = spamdscan_socket (priv->file, selected, spam_mark, cfg, &symbols);
		}
		else {
			r = rspamdscan_socket (ctx, priv, selected, spam_mark, cfg, &symbols);
		}
		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("spamdscan: unexpected problem, %s, %s", selected->name, priv->file);
			break;
		}
		if (--retry < 1) {
			msg_warn("spamdscan: retry limit exceeded, %s, %s", selected->name, priv->file);
			break;
		}
		msg_warn("spamdscan: failed to scan, retry, %s, %s", selected->name, priv->file);
		sleep(1);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday(&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;

	if (r == 1) {
		msg_info("spamdscan: scan %f, %s, spam found [%f/%f], %s, %s", tf - ts,
					selected->name, 
					spam_mark[0], spam_mark[1],
					(symbols != NULL) ? symbols : "no symbols", priv->file);
		if (symbols != NULL) {
			free (symbols);
		}
	}
	else {
		msg_info("spamdscan: scan %f, %s, no spam [%f/%f], %s, %s", tf -ts, 
					selected->name,
					spam_mark[0], spam_mark[1], 
					(symbols != NULL) ? symbols : "no symbols", priv->file);
		if (symbols != NULL) {
			free (symbols);
		}
	}
	symbols = NULL;
	/* try to scan extra servers */
	if (cfg->extra_spamd_servers_num > 0) {
		selected = (struct spamd_server *) get_random_upstream ((void *)cfg->extra_spamd_servers,
											cfg->extra_spamd_servers_num, sizeof (struct spamd_server),
											t.tv_sec, cfg->spamd_error_time, cfg->spamd_dead_time, cfg->spamd_maxerrors);
		if (selected == NULL) {
			msg_err ("spamdscan: upstream get error, %s", priv->file);
		}
		else {
			if (selected->type == SPAMD_SPAMASSASSIN) {
				r1 = spamdscan_socket (priv->file, selected, spam_mark, cfg, &symbols);
			}
			else {
				r1 = rspamdscan_socket (ctx, priv, selected, spam_mark, cfg, &symbols);
			}
			gettimeofday(&t, NULL);
			tf = t.tv_sec + t.tv_usec / 1000000.0;
			if (r1 == 0 || r1 == 1) {
				upstream_ok (&selected->up, t.tv_sec);
				if (r1 == 1) {
					msg_info("spamdscan: scan %f, %s, spam found [%f/%f], %s, %s", tf - ts,
								selected->name, 
								spam_mark[0], spam_mark[1],
								(symbols != NULL) ? symbols : "no symbols", priv->file);
					if (symbols != NULL) {
						free (symbols);
					}
				}
				else {
					msg_info("spamdscan: scan %f, %s, no spam [%f/%f], %s, %s", tf -ts, 
								selected->name,
								spam_mark[0], spam_mark[1], 
								(symbols != NULL) ? symbols : "no symbols", priv->file);
					if (symbols != NULL) {
						free (symbols);
					}
				}
			}
			else {
				upstream_fail (&selected->up, t.tv_sec);
				if (r1 == -2) {
					msg_warn("spamdscan: unexpected problem, %s, %s", selected->name, priv->file);
				}
			}
		}
	}


	return r;
}

/* 
 * vi:ts=4 
 */
