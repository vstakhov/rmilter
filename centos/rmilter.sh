#!/bin/sh
#
# rmilter - this script starts and stops the rmilter daemon
#
# chkconfig:   - 85 15 
# description:  rmilter is a spam filtering system
# processname: rmilter
# config:      /etc/rmilter/rmilter.sysvinit.conf
# config:      /etc/sysconfig/rmilter
# pidfile:     /var/run/rmilter/rmilter.pid

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ "$NETWORKING" = "no" ] && exit 0

rmilter="/usr/sbin/rmilter"
prog=$(basename $rmilter)

rmilter_CONF_FILE="/etc/rmilter/rmilter.conf.sysvinit"
rmilter_USER="rmilter"
rmilter_GROUP="rmilter"

[ -f /etc/sysconfig/rmilter ] && . /etc/sysconfig/rmilter

lockfile=/var/lock/subsys/rs

start() {
    [ -x $rmilter ] || exit 5
    [ -f $rmilter_CONF_FILE ] || exit 6
    echo -n $"Starting $prog: "
    daemon --user=$rmilter_USER $rmilter -c $rmilter_CONF_FILE
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}

stop() {
    echo -n $"Stopping $prog: "
    killproc $prog -QUIT
    retval=$?
    if [ $retval -eq 0 ]; then
        if [ "$CONSOLETYPE" != "serial" ]; then
           echo -en "\\033[16G"
        fi
        while rh_status_q
        do
            sleep 1
            echo -n $"."
        done
        rm -f $lockfile
    fi
    echo
    return $retval
}

restart() {
    configtest || return $?
    stop
    start
}

reload() {
    configtest || return $?
    echo -n $"Reloading $prog: "
    killproc $rmilter -HUP
    RETVAL=$?
    echo
}

force_reload() {
    restart
}

configtest() {
  $rmilter -t -c $RMILTER_CONF_FILE
}

rh_status() {
    status $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}

case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart|configtest)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    force-reload)
        force_reload
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
	    ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-restart|reload|force-reload|configtest}"
        exit 2
esac

