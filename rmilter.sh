#!/bin/sh
#
# $Id$
#
# PROVIDE: rmilter
# REQUIRE: LOGIN
# BEFORE: postfix
# KEYWORD: shutdown

#
# Add the following line to /etc/rc.conf to enable countd:
# rmilter (bool):          Set to "NO" by default.
#                          Set it to "YES" to enable rmilter.

. /etc/rc.subr

name="rmilter"
rcvar=`set_rcvar`
procname="/usr/local/sbin/rmilter"

load_rc_config $name

: ${rmilter_enable="NO"}
: ${rmilter_pidfile="/var/run/rmilter/rmilter.pid"}
: ${rmilter_socket="/var/run/rmilter/sock"}
: ${rmilter_user="rmilter"}

stop_postcmd="rm -f $rmilter_pidfile $rmilter_socket"
start_precmd="rm -f $rmilter_socket"

command=${procname}
command_args="-c /usr/local/etc/rmilter.conf"

run_rc_command "$1"
