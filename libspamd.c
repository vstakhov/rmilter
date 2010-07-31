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
#include <ctype.h>
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
#include <math.h>

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
static const char* sym_metric = "^Metric: ([^;]+); (True|False); (-?\\d+\\.?\\d*) / (-?\\d+\\.?\\d*)$";
static const char* sym_symbol = "^Symbol: ([^;]+);?.*$";
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

static int
check_symbols (char *symbols_got, char *symbols_check)
{
	char *p, *s, t;

	p = symbols_check;
	s = p;

	while (*p) {
		if (*p == ' ' || *p == ',') {
			/* Try to find this symbol */
			t = *p;
			*p = '\0';
			if (strstr (symbols_got, p) != NULL) {
				*p = t;
				return 1;
			}
			*p = t;
			while (*p == ' ' || *p == ',') {
				p ++;
			}
			s = p;
		}
		p ++;
	}

	return 0;
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
rspamdscan_socket(SMFICTX *ctx, struct mlfi_priv *priv, const struct spamd_server *srv, struct config_file *cfg, rspamd_result_t *res, char **mid)
{
	char buf[16384];
	char *c, *p, *err_str;
	struct sockaddr_un server_un;
	struct sockaddr_in server_in;
	int s, r, fd, ofl, size = 0, to_write, written, state, next_state, toklen;
	int remain;
	struct stat sb;
	struct rspamd_metric_result *cur = NULL;
	struct rspamd_symbol *cur_symbol;

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
	
	r = 0;
	to_write = sizeof (buf) - r;
	written = snprintf (buf + r, to_write, "SYMBOLS RSPAMC/1.2\r\nContent-length: %ld\r\n", (long int)sb.st_size);
	if (written > to_write) {
		msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
		close(fd);
		close(s);
		return -1;
	}
	r += written;

	if (priv->priv_rcpt[0] != '\0') {
		to_write = sizeof (buf) - r;
		written = snprintf (buf + r, to_write, "Rcpt: %s\r\n", priv->priv_rcpt);
		if (written > to_write) {
			msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
			close(fd);
			close(s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_from[0] != '\0') {
		to_write = sizeof (buf) - r;
		written = snprintf (buf + r, to_write, "From: %s\r\n", priv->priv_from);
		if (written > to_write) {
			msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
			close(fd);
			close(s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_helo[0] != '\0') {
		to_write = sizeof (buf) - r;
		written = snprintf (buf + r, to_write, "Helo: %s\r\n", priv->priv_helo);
		if (written > to_write) {
			msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
			close(fd);
			close(s);
			return -1;
		}
		r += written;
	}
	if (priv->priv_ip[0] != '\0') {
		to_write = sizeof (buf) - r;
		written = snprintf (buf + r, to_write, "IP: %s\r\n", priv->priv_ip);
		if (written > to_write) {
			msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
			close(fd);
			close(s);
			return -1;
		}
		r += written;
	}

	to_write = sizeof (buf) - r;
	written = snprintf (buf + r, to_write, "Queue-ID: %s\r\n\r\n", priv->mlfi_id);
	if (written > to_write) {
		msg_warn("rspamd: buffer overflow while filling buffer (%s)", srv->name);
		close(fd);
		close(s);
		return -1;
	}
	r += written;

	if (write (s, buf, r) == -1) {
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
	size = 0;
	
	/* XXX: in fact here should be some FSM to parse reply and this one just skip long replies */
	while ((r = read(s, buf + size, sizeof (buf) - size - 1)) > 0 && size < sizeof (buf) - 1) {
		size += r;
	}

	if (r < 0) {
		msg_warn("rspamd: read, %s, %d: %m", srv->name, errno);
		close(s);
		return -1;
	}
	buf[size] = '\0';
	close(s);

#define TEST_WORD(x)																\
do {																				\
	if (remain < sizeof ((x)) - 1 || memcmp (p, (x), sizeof ((x)) - 1) != 0) {		\
		msg_warn ("invalid reply from server %s at state %d, expected: %s, got %*s", srv->name, state, ((x)), (int)sizeof((x)), p);				\
		return -1;																	\
	}																				\
	p += sizeof((x)) - 1;															\
	remain -= sizeof((x)) - 1;														\
} while (0)


	c = buf;
	p = buf;
	remain = size - 1;
	state = 0;
	next_state = 100;

	while (remain > 0) {
		switch (state) {
			case 0:
				/*
				 * Expect first reply line:
				 * RSPAMD/{VERSION} {ERROR_CODE} {DESCR} CRLF
				 */
				TEST_WORD("RSPAMD/");
				if ((c = strchr (p, ' ')) == NULL) {
					msg_warn ("invalid reply from server %s on state %d", srv->name, state);
					return -1;
				}
				/* Well now in c we have space symbol, skip all */
				while (remain > 0 && isspace (*c)) {
					c ++;
				}
				/* Now check code */
				if (*c != '0') {
					msg_warn ("invalid reply from server %s on state %d, code: %c", srv->name, state, *c);
					return -1;
				}
				/* Now skip everything till \n */
				if ((c = strchr (c, '\n')) == NULL) {
					msg_warn ("invalid reply from server %s on state %d", srv->name, state);
					return -1;
				}
				c ++;
				remain -= c - p;
				p = c;
				next_state = 2;
				state = 99;
				break;
			case 2:
				/*
				 * In this state we compare begin of line with Metric:
				 */
				TEST_WORD("Metric:");
				cur = malloc (sizeof (struct rspamd_metric_result));
				if (cur == NULL) {
					msg_err ("malloc failed: %s", strerror (errno));
					return -1;
				}
				TAILQ_INIT(&cur->symbols);
				next_state = 3;
				state = 99;
				break;
			case 3:
				/* 
				 * In this state we parse metric line 
				 * Typical line looks as name; result; score1 / score2[ / score3] and we are interested in:
				 * name, result, score1 and score2
				 */
				if ((c = strchr (p, ';')) == NULL) {
					msg_warn ("invalid reply from server %s on state %d, at position: %s", srv->name, state, p);
					return -1;
				}
				/* Now in c we have end of name and in p - begin of name, so copy this data to temp buffer */
				cur->metric_name = malloc (c - p + 1);
				if (cur->metric_name == NULL) {
					msg_err ("malloc failed: %s", strerror (errno));
					return -1;
				}
				strlcpy (cur->metric_name, p, c - p + 1);
				remain -= c - p + 1;
				p = c + 1;
				/* Now skip result from rspamd, just extract 2 numbers */
				if ((c = strchr (p, ';')) == NULL) {
					msg_warn ("invalid reply from server %s on state %d, at position: %s", srv->name, state, p);
					return -1;
				}
				remain -= c - p + 1;
				p = c + 1;
				/* Now skip spaces */
				while (isspace (*p) && remain > 0) {
					p ++;
					remain --;
				}
				/* Try to read first mark */
				cur->score = strtod (p, &err_str);
				if (err_str != NULL && (*err_str != ' ' && *err_str != '/')) {
					msg_warn ("invalid reply from server %s on state %d, error converting score number: %s", srv->name, state, err_str);
					return -1;
				}
				remain -= err_str - p;
				p = err_str;
				while (remain > 0 && (*p == ' ' || *p == '/')) {
					remain --;
					p ++;
				}
				/* Try to read second mark */
				cur->required_score = strtod (p, &err_str);
				if (err_str != NULL && (*err_str != ' ' && *err_str != '/' && *err_str != '\r')) {
					msg_warn ("invalid reply from server %s on state %d, error converting required score number: %s", srv->name, state, err_str);
					return -1;
				}
				remain -= err_str - p;
				p = err_str;
				while (remain > 0 && *p != '\n') {
					remain --;
					p ++;
				}
				state = 99;
				next_state = 4;
				break;
			case 4:
				/* Symbol/Action */
				if (remain >= sizeof ("Symbol:") && memcmp (p, "Symbol:", sizeof ("Symbol:") - 1) == 0) {
					state = 99;
					next_state = 5;
					p += sizeof("Symbol:") - 1;															\
					remain -= sizeof("Symbol:") - 1;
				}
				else if (remain >= sizeof ("Action:") && memcmp (p, "Action:", sizeof ("Action:") - 1) == 0) {
					state = 99;
					next_state = 6;
					p += sizeof("Action:") - 1;															\
					remain -= sizeof("Action:") - 1;
				}
				else if (remain >= sizeof ("Metric:") && memcmp (p, "Metric:", sizeof ("Metric:") - 1) == 0) {
					state = 99;
					next_state = 3;
					p += sizeof("Metric:") - 1;															\
					remain -= sizeof("Metric:") - 1;
					TAILQ_INSERT_HEAD(res, cur, entry);
					cur = malloc (sizeof (struct rspamd_metric_result));
					if (cur == NULL) {
						msg_err ("malloc failed: %s", strerror (errno));
						return -1;
					}
					TAILQ_INIT(&cur->symbols);
				}
				else if (remain >= sizeof ("Message-ID:") && memcmp (p, "Message-ID:", sizeof ("Message-ID:") - 1) == 0) {
					state = 99;
					next_state = 7;
					p += sizeof("Message-ID:") - 1;															\
					remain -= sizeof("Message-ID:") - 1;
				}
				else {
					toklen = strcspn (p, "\r\n");
					if (toklen > remain) {
						msg_info ("bad symbol name detected");
						return -1;
					}
					remain -= toklen;
					p += toklen;
					next_state = 4;
					state = 99;
				}
				break;
			case 5:
				/* Parse symbol line */
				toklen = strcspn (p, ";\r\n");
				if (toklen == 0 || toklen > remain) {
					/* Bad symbol name */
					msg_info ("bad symbol name detected");
					return -1;
				}
				cur_symbol = malloc (sizeof (struct rspamd_symbol));
				if (cur_symbol == NULL) {
					msg_err ("malloc failed: %s", strerror (errno));
					return -1;
				}
				cur_symbol->symbol = malloc (toklen + 1);
				if (cur_symbol->symbol == NULL) {
					msg_err ("malloc failed: %s", strerror (errno));
					return -1;
				}
				strlcpy (cur_symbol->symbol, p, toklen + 1);
				TAILQ_INSERT_HEAD (&cur->symbols, cur_symbol, entry);
				/* Skip to the end of line */
				toklen = strcspn (p, "\r\n");
				if (toklen > remain) {
					msg_info ("bad symbol name detected");
					return -1;
				}
				remain -= toklen;
				p += toklen;
				next_state = 4;
				state = 99;
				break;
			case 6:
				/* Parse action */
				if (memcmp (p, "reject", sizeof ("reject")) == 0) {
					cur->action = METRIC_ACTION_REJECT;
				}
				else if (memcmp (p, "greylist", sizeof ("greylist")) == 0) {
					cur->action = METRIC_ACTION_REJECT;
				}
				else {
					cur->action = METRIC_ACTION_NOACTION;
				}
				/* Skip to the end of line */
				toklen = strcspn (p, "\r\n");
				if (toklen > remain) {
					msg_info ("bad symbol name detected");
					return -1;
				}
				remain -= toklen;
				p += toklen;
				next_state = 4;
				state = 99;
				break;
			case 7:
				/* Parse message id */
				toklen = strcspn (p, "\r\n");
				*mid = malloc (toklen + 1);
				strlcpy (*mid, p, toklen + 1);
				remain -= toklen;
				p += toklen;
				next_state = 4;
				state = 99;
				break;
			case 99:
				/* Skip spaces */
				if (isspace (*p)) {
					p ++;
					remain --;
				}
				else {
					state = next_state;
				}
				break;
			default:
				msg_err ("state machine breakage detected, state = %d, p = %s", state, p);
				return -1;
		}
	}

	if (cur != NULL) {
		TAILQ_INSERT_HEAD(res, cur, entry);
	}
	return 0;
}
#undef TEST_WORD
/*
 * spamdscan_socket() - send file to specified host. See spamdscan() for
 * load-balanced wrapper.
 * 
 * returns 0 when spam not found, 1 when spam found, -1 on some error during scan (try another server), -2
 * on unexpected error (probably clamd died on our file, fallback to another
 * host not recommended)
 */

static int 
spamdscan_socket(const char *file, const struct spamd_server *srv, struct config_file *cfg, rspamd_result_t *res)
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
	int s, r, fd, ofl, size = 0;
	struct stat sb;
	struct rspamd_metric_result *cur = NULL;
	struct rspamd_symbol *cur_symbol;

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

	while ((r = read(s, buf + size, sizeof (buf) - size - 1)) > 0 && size < sizeof (buf) - 1) {
		size += r;
	}
	buf[size] = 0;

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
		cur = malloc (sizeof (struct rspamd_metric_result));
		if (cur == NULL) {
			msg_err ("malloc falied: %s", strerror (errno));
			return -1;
		}
		bzero (cur, sizeof (struct rspamd_metric_result));
		/* Find mark */
		c = strchr (c, ';');
		if (c != NULL && *c != '\0') {
			cur->score = strtod (c + 1, &err);
			if (*err == ' ' && *(err + 1) == '/') {
				cur->required_score = strtod (err + 3, NULL);
			}
			else {
				cur->score = 0;
			}
		}
		else {
			cur->score = 0;
			cur->required_score = 0;
		}
	}

	/* Skip empty lines */
	while (*c && *c++ != '\n');
	while (*c++ && (*c == '\r' || *c == '\n'));
	/* Write symbols */
	if (*c != '\0') {
		err = strchr (c, '\r');
		if (err != NULL) {
			*err = '\0';
		}
		cur_symbol = malloc (sizeof (struct rspamd_symbol));
		cur_symbol->symbol = strdup (c);
		TAILQ_INSERT_HEAD(&cur->symbols, cur_symbol, entry);
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
 * 1 if file scanned and spam found ,
 * 2 if file scanned and this is probably spam,
 * -1 when retry limit exceeded, -2 on unexpected error, e.g. unexpected reply from
 * server (suppose scanned message killed spamd...)
 */

int 
spamdscan(SMFICTX *ctx, struct mlfi_priv *priv, struct config_file *cfg)
{
	int retry = 5, r = -2;
	struct timeval t;
	double ts, tf;
	struct spamd_server *selected = NULL;
	char rbuf[BUFSIZ];
	char *prefix = "s", *mid = NULL;
	rspamd_result_t res;
	struct rspamd_metric_result *cur = NULL, *tmp;
	struct rspamd_symbol *cur_symbol, *tmp_symbol;
	enum rspamd_metric_action res_action = METRIC_ACTION_NOACTION;
	

	gettimeofday(&t, NULL);
	ts = t.tv_sec + t.tv_usec / 1000000.0;

	TAILQ_INIT(&res);

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
			prefix = "s";
			r = spamdscan_socket (priv->file, selected, cfg, &res);
		}
		else {
			prefix = "rs";
			r = rspamdscan_socket (ctx, priv, selected, cfg, &res, &mid);
		}
		if (r == 0 || r == 1) {
			upstream_ok (&selected->up, t.tv_sec);
			break;
		}
		upstream_fail (&selected->up, t.tv_sec);
		if (r == -2) {
			msg_warn("%spamdscan: unexpected problem, %s, %s", prefix, selected->name, priv->file);
			break;
		}
		if (--retry < 1) {
			msg_warn("%spamdscan: retry limit exceeded, %s, %s", prefix, selected->name, priv->file);
			break;
		}
		msg_warn("%spamdscan: failed to scan, retry, %s, %s", prefix, selected->name, priv->file);
		sleep(1);
	}

	/*
	 * print scanning time, server and result
	 */
	gettimeofday(&t, NULL);
	tf = t.tv_sec + t.tv_usec / 1000000.0;
	
	/* Parse res tailq */
	cur = TAILQ_FIRST(&res);
	while (cur) {
		if (cur->metric_name) {
			r = snprintf (rbuf, sizeof (rbuf), "spamdscan: scan qid: <%s>, mid: <%s>, %f, %s, metric: %s: [%f / %f], symbols: ",
					priv->mlfi_id,
					(mid != NULL) ? mid : "undef",
					tf - ts,
					selected->name,
					cur->metric_name,
					cur->score,
					cur->required_score);
			free (cur->metric_name);
		}
		else {
			r = snprintf (rbuf, sizeof (rbuf), "spamdscan: scan <%s>, %f, %s, metric: default: [%f / %f], symbols: ",
					priv->mlfi_id,
					tf - ts,
					selected->name,
					cur->score,
					cur->required_score);
		
		}
		if (cur->action < res_action) {
			res_action = cur->action;
		}
		/* Write symbols */
		cur_symbol = TAILQ_FIRST(&cur->symbols);
		if (cur_symbol == NULL) {
			r += snprintf (rbuf + r, sizeof (rbuf) - r, "no symbols");
		}
		else {
			while (cur_symbol) {
				if (cur_symbol->symbol) {
					if (TAILQ_NEXT (cur_symbol, entry)) {
						r += snprintf (rbuf + r, sizeof (rbuf) - r, "%s, ", cur_symbol->symbol);
					}
					else {
						r += snprintf (rbuf + r, sizeof (rbuf) - r, "%s", cur_symbol->symbol);
					}
					free (cur_symbol->symbol);
				}
				tmp_symbol = cur_symbol;
				cur_symbol = TAILQ_NEXT(cur_symbol, entry);
				free (tmp_symbol);
			}
		}
		msg_info ("%s", rbuf);
		tmp = cur;
		cur = TAILQ_NEXT(cur, entry);
		free (tmp);
	}
	if (res_action == METRIC_ACTION_REJECT) {
		return 1;
	}
	else if (res_action == METRIC_ACTION_GREYLIST) {
		return 2;
	}

	return 0;
#if 0
	/* XXX: Enable this functionality some time */
	if (cfg->extra_spamd_servers_num > 0) {
		selected = (struct spamd_server *) get_random_upstream ((void *)cfg->extra_spamd_servers,
											cfg->extra_spamd_servers_num, sizeof (struct spamd_server),
											t.tv_sec, cfg->spamd_error_time, cfg->spamd_dead_time, cfg->spamd_maxerrors);
		if (selected == NULL) {
			msg_err ("spamdscan: upstream get error, %s", priv->file);
		}
		else {
			if (selected->type == SPAMD_SPAMASSASSIN) {
				r1 = spamdscan_socket (priv->file, selected, extra_mark, cfg, symbols);
			}
			else {
				r1 = rspamdscan_socket (ctx, priv, selected, extra_mark, cfg, symbols);
			}
			gettimeofday(&t, NULL);
			tf = t.tv_sec + t.tv_usec / 1000000.0;
			if (r1 == 0 || r1 == 1) {
				upstream_ok (&selected->up, t.tv_sec);
				if (r1 == 1) {
					msg_info("%spamdscan: scan %f, %s, spam found [%f/%f], %s, %s", 
								selected->type == SPAMD_SPAMASSASSIN ? "s" : "rs",
								tf - ts,
								selected->name, 
								extra_mark[0], extra_mark[1],
								(*symbols != NULL) ? *symbols : "no symbols", priv->file);
				}
				else {
					msg_info("%spamdscan: scan %f, %s, no spam [%f/%f], %s, %s", 
								selected->type == SPAMD_SPAMASSASSIN ? "s" : "rs",
								tf -ts, 
								selected->name,
								extra_mark[0], extra_mark[1], 
								(*symbols != NULL) ? *symbols : "no symbols", priv->file);
				}
				if (r1 != r && cfg->diff_dir != NULL) {
					snprintf (copyfile, sizeof (copyfile), "%s/%s", cfg->diff_dir, priv->mlfi_id);
					msg_info ("spamdscan: results from check servers are different, saving to %s", copyfile);
					cfd = open (copyfile, O_WRONLY | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					if (cfd == -1) {
						msg_warn ("spamdscan: cannot create file %s, %m", copyfile);
					}
					else {
						/* XXX: should check for return values */
						rfd = open(priv->file, O_RDONLY);
						if (rfd == -1) {
							msg_warn ("spamdscan: cannot open file %s, %m", priv->file);
						}
						else {
							while ((r1 = read (rfd, rbuf, sizeof (rbuf))) > 0) {
								if (write (cfd, rbuf, r1) == -1) {
									msg_warn ("spamdscan: write error while writing to %s: %m", copyfile);
									break;
								}
							}
							close (rfd);
						}
						close (cfd);
					}
				}

				if (*symbols && cfg->check_symbols != NULL && cfg->symbols_dir != NULL) {
					if (check_symbols (*symbols, cfg->check_symbols)) {
						snprintf (copyfile, sizeof (copyfile), "%s/%s", cfg->symbols_dir, priv->mlfi_id);
						msg_info ("spamdscan: found symbols from list, saving to %s", copyfile);
						cfd = open (copyfile, O_WRONLY | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
						if (cfd == -1) {
							msg_warn ("spamdscan: cannot create file %s, %m", copyfile);
						}
						else {
							/* XXX: should check for return values */
							rfd = open(priv->file, O_RDONLY);
							if (rfd == -1) {
								msg_warn ("spamdscan: cannot open file %s, %m", priv->file);
							}
							else {
								while ((r1 = read (rfd, rbuf, sizeof (rbuf))) > 0) {
									if (write (cfd, rbuf, r1) == -1) {
										msg_warn ("spamdscan: write error while writing to %s: %m", copyfile);
										break;
									}
								}
								close (rfd);
							}
							close (cfd);
						}
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
#endif

	return r;
}

/* 
 * vi:ts=4 
 */
