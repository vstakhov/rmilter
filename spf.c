/*
 * $Id$
 */


#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <db.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include <sys/mman.h>

#include "spf2/spf.h"
#include "cfg_file.h"
#include "spf.h"
#include "rmilter.h"

/* Defined in rmilter.c */
extern int my_strcmp (const void *, const void *);

int
spf_check(struct mlfi_priv *priv, struct config_file *cfg)
{
	struct sockaddr_in *sa = &priv->priv_addr;
	char *helo = priv->priv_helo;
	char *fromp = priv->priv_from;
	SPF_server_t *spf_server;
	SPF_request_t *spf_request;
	SPF_response_t *spf_response;
	char from[NS_MAXDNAME + 1];
	int res, result = 0;
	char *domain_pos;
	size_t len;

	/*
	 * And the enveloppe source e-mail
	 */
	if (fromp[0] == '<')
		fromp++; /* strip leading < */
	strlcpy (from, fromp, NS_MAXDNAME);
	from[NS_MAXDNAME] = '\0';
	len = strlen(from);
	if (fromp[len - 1] == '>')
		from[len - 1] = '\0'; /* strip trailing > */
	domain_pos = strchr (from, '@');
	
	/* No domain part in envfrom field - do not make spf check */
	if (domain_pos == NULL) {
		return 1;	
	}
	
	/* Search in spf_domains array */
	if (! bsearch ((void *) domain_pos, cfg->spf_domains, sizeof (char *), 
		cfg->spf_domains_num, my_strcmp)) {
		/* Domain not found, stop check */
		return 1;
	}

	if ((spf_server = SPF_server_new (SPF_DNS_CACHE, 0)) == NULL) {
		syslog(LOG_ERR, "SPF_server_new failed");
		goto out1;
	}

	if ((spf_request = SPF_request_new (spf_server)) == NULL) {
		syslog (LOG_ERR, "SPF_request_new failed");
		goto out2;
	}

	/*
	 * Get the IP address
	 */
	switch (sa->sin_family) {
	case AF_INET:
		res = SPF_request_set_ipv4 (spf_request, sa->sin_addr);
		break;
	default:
		syslog (LOG_ERR, "unknown address family %d", sa->sin_family);
		goto out3;
	}
	if (res != 0) {
		syslog (LOG_ERR, "SPF_request_set_ip_str failed");
		goto out3;
	}

	/* HELO string */
	if (SPF_request_set_helo_dom (spf_request, helo) != 0) {
		syslog (LOG_ERR, "SPF_request_set_helo_dom failed");
		goto out3;
	}


	if (SPF_request_set_env_from (spf_request, from) != 0) {
		syslog (LOG_ERR, "SPF_request_set_env_from failed");
		goto out3;
	}

	/*
	 * Get the SPF result
	 */
	SPF_request_query_mailfrom (spf_request, &spf_response);
	if ((res = SPF_response_result (spf_response)) == SPF_RESULT_PASS)
		result = 1;

	SPF_response_free (spf_response);
out3:
	SPF_request_free (spf_request);
out2:
	SPF_server_free (spf_server);
out1:

	return result;
}
