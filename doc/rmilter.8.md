% RMILTER(8) Rmilter User Manual

# NAME

rmilter - Another milter for different mail checks.

# SYNOPSIS

rmilter [*options*]...

rmilter -h

# DESCRIPTION

Rmilter is used to integrate Rspamd with milter compatible MTA, for example Postfix or Sendmail.

# OPTIONS

-c *path*
:	Specify config file(s)

# EXAMPLES

Run rmilter in foreground with custom configuration:

	rmilter -c ~/rmilter.conf

# SEE ALSO

Rmilter documentation and source codes may be downloaded from
<https://rspamd.com/rmilter/>.
