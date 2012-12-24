#
# Regular cron jobs for the rmilter package
#
0 4	* * *	root	[ -x /usr/bin/rmilter_maintenance ] && /usr/bin/rmilter_maintenance
