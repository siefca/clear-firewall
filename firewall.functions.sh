# functions file for firewall configurator --
# IPtables configuration script.
#
# Copyright (c) 2001-2003 by Pawel Wilk <siefca@gnu.org>
#
# This is Free Software. You can redistribute it and/or
# modify under the terms of GNU General Public License 
# - version 2 or later. If you don't have a copy of the
# license look for it at http://www.gnu.org/. This tool
# comes with absolutely NO WARRANTY. Use it at your own
# risk.
#

ipt="/usr/sbin/iptables"

function reset_internal_vars
{
    lastchainname=""
    lastnetdevname=""
    chain_default_reject=""
    lastports=""
    after_ads=""
    last_state=""
}

#
# creates new, clean chain
#
function services_set
{
    $ipt --flush "$1" 2>/dev/null		# REMOVAL REQUIRED
    $ipt --delete-chain "$1" 2>/dev/null	# when fw-down will be made
    $ipt --new-chain "$1" 2>/dev/null || { last_state = "s_awaiting"; return; }
    lastchainname="$1"
    lastports="";
    lastnetdevname="";
    after_ads="";
    last_state="services_set"
}

#
# this function sets the jump rule for well known TCP
# services which our host is offering outside
# it takes two arguments: chain name and service
# names/numbers separated by period sign
# remember to concatenate the string argument
# by putting quotes around
# 
# this SHOULD NOT BE invoked from configuration
# since add_service() function is present!
# the good moment for it is on first invocation
# of the allow_connect() and drop_connect() functions
# 
function services_ports
{
    if echo "$1" | grep -q ","
    then
	$ipt -A "$current_chain"	--protocol tcp \
					--match multiport \
					--destination-port "$1" \
					--match state \
					--state NEW \
					-j "$lastchainname"
    else
	$ipt -A $current_chain		--protocol tcp \
					--destination-port "$1" \
					--match state \
					--state NEW \
					-j "$lastchainname"
    fi
    last_state="services_ports"
}

#
# it just sets the device name
# without any nasty tree structure
# the device name is just added to
# each newly created allow-entry
#
function interface
{
    if [ x$1 = "x!" ]; then
	iname="! $2"
    else
	iname="$1"
    fi
    lastnetdevname="$iname"
    last_state="interface"
}


#
# it adds port number/service name on each invocation
#
function add_service
{
    # tutaj case na last_state i jesli awaiting to return
    if [ x$lastports = x ]; then
	lastports="$1"
    else
	lastports="$lastports,$1"
    fi
    last_state="add"
}

function service
{
    add_service "$1"
}

function services
{
    add_service "$1"
}

function add_services
{
    add_service "$1"
}

#
# adds some source address to our services chain
#
function core_connect
{
    if [ x$last_state = xadd ]; then
	services_ports "$lastports"
    fi

    if [ x$last_state != xcore_recursive ]; then
	OLDIFS="$IFS"
	IFS=','
	for i in `echo "$lastnetdevname"`
	do
	    last_state="core_recursive"
    	    core_connect "$i" "$1" "$2" "$3"
	done
	IFS="$OLDIFS"
    fi
    
    if [[ x$1 = xall || x$1 = x ]]; then
	intervocation=""
    else
	intervocation="--in-interface $1"
    fi
    if [ x$4 = x ]; then
	$ipt -A "$lastchainname" $intervocation --source "$3" -j "$1"
    else
	$ipt -A "$lastchainname" $intervocation --source "$3" --destination "$4" -j "$2"
    fi
    last_state="core_connnect"
}

# and related functions are...
function allow_connect
{
    core_connect ACCEPT $1 $2
}

function accept_connect
{
    core_connect ACCEPT $1 $2
}

function allow
{
    core_connect ACCEPT $1 $2
}

function accept
{
    core_connect ACCEPT $1 $2
}

function drop
{
    core_connect DROP $1 $2
}

function deny
{
    core_connect DROP $1 $2
}

function drop_connect
{
    core_connect DROP $1 $2
}

function deny_connect
{
    core_connect DROP $1 $2
}

function reject
{
    core_connect REJECT $1 $2
}

function reject_connect
{
    core_connect REJECT $1 $2
}

#
# self explanatory ;P
#
function flush_rules
{
    $ipt --flush $current_chain
    last_state="flush_rules"
}

function default_policy
{
    if [ x$1 = xREJECT ]; then
	chain_default_reject="yes"
	$ipt -P $current_chain DROP
    else
	$ipt -P $current_chain "$1"
    fi
    last_state="default_policy"
}

#
# good way to close the chain
#
function reject_other
{
    $ipt -A "$lastchainname" -j REJECT
    last_state="reject_other"
}


function accept_other
{
    $ipt -A "$lastchainname" -j ACCEPT
    last_state="accept_other"
}


function drop_other
{
    $ipt -A "$lastchainname" -j DROP
    last_state="drop_other"
}

function deny_other
{
    $ipt -A "$lastchainname" -j DROP
    last_state="deny_other"
}


#
# important function
#
function graceful_exit ()
{
    $ipt -A $current_chain --match state --state RELATED,ESTABLISHED -j ACCEPT
    if [ ! x$chain_default_reject = x ]; then
	iptables -A $current_chain -j REJECT
    fi
    last_state="graceful_exit"
}

