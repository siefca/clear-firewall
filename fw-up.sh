#!/bin/sh

# IPtables configuration script.
#
# Copyright (c) 2001-2003 by Pawel Wilk <siefca@gnu.org>
#
# This is Free Software. You can redistribute it and/or modify under the terms
# of GNU General Public License - version 2 or later. If you don't have a copy
# of the license look for it at http://www.gnu.org/. This tool comes with
# absolutely NO WARRANTY. Use it at your own risk.
#

# load basic modules
#
/sbin/insmod ip_tables 2>/dev/null
/sbin/insmod iptable_filter 2>/dev/null
/sbin/insmod ipt_REJECT 2>/dev/null
/sbin/insmod ipt_state 2>/dev/null
/sbin/insmod ip_conntrack 2>/dev/null
/sbin/insmod ipt_multiport 2>/dev/null
/sbin/insmod ip_conntrack_ftp 2>/dev/null


# lookin' good shortcut
#
ipt="/usr/sbin/iptables"

$ipt -P INPUT ACCEPT
$ipt -F INPUT
$ipt -F

exit 0


echo -n "Bringing up firewalling "

# load fundamental functions
#
. /etc/firewall/firewall.functions.sh

# load and parse chains
#
for current_chain in INPUT OUTPUT FORWARD
do
    if [ -f /etc/firewall/$current_chain ]; then
	reset_internal_vars
	flush_rules
	. /etc/firewall/$current_chain
	echo -n "($current_chain) "
	graceful_exit
    fi
done

echo " done!"

# TODO: fw using PGID and UID?
# 

