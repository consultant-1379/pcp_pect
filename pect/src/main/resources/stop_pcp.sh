#!/bin/bash
# ----------------------------------------------------------------------
# Packet Capture Pre-Processor
#
# Usage:
#
#       ./stop_pcp.bsh
#
#	    exit 0 for success
#
#       Author: Luke Potter - elukpot
#
#       Date: 18/06/13
#
#       Description:
#           This script stops the PCP server by killing its process.
# 
# ----------------------------------------------------------------------
# Copyright (c) 1999 - 2013 AB Ericsson Oy  All rights reserved.
# ----------------------------------------------------------------------
# Version 1.4
# Version 1.5  Fix for /dev/pts/3 permission denied, preventing restart
# Version 1.6  Fix for this script issuing sleep and not stopping pcp; added kill -9 option
# ----------------------------------------------------------------------
echo "INFO  broadcast - Stopping Packet Capture Pre-Processor." 
PCP_HOME=/opt/ericsson/pcp/pect/pect
cd $PCP_HOME
PCP_TTY_TERMINAL=$PCP_HOME/pcp_tty
DEFAULT_PCP_PROMPT="[pcpuser]$"
PCP_PROMPT_FILE=$PCP_HOME/pcp_prompt
STOP_TIMEOUT=240
CACHE_TMP_FILE="/var/opt/ericsson/pcp/cache/gtpc.cache-001.tmp"
WRITING_CACHE=0
LOOP_COUNTER=0

if [[ -s $PCP_PROMPT_FILE && -r $PCP_PROMPT_FILE ]]; then
    PCP_PROMPT=$(cat $PCP_PROMPT_FILE)
else
    PCP_PROMPT=$DEFAULT_PCP_PROMPT
fi
  
#Remove Monitoring from cron
$PCP_HOME/pcp-cronUpdate remove_monitor

# Get the Processes IDs and put them into the processes file
kill -TERM $(ps -ef | grep pcpuser | grep "pcp-pec[t]" | awk '{print $2}' )  
while kill -0  $(ps -ef | grep pcpuser | grep "pcp-pec[t]" | grep -v grep | awk '{print $2}' | tail -n 1) > /dev/null 2>&1
do
	sleep 1
	if [ $LOOP_COUNTER -eq 0 ] ; then  
        echo -n "INFO  broadcast - Closing Streams"
	fi
	LOOP_COUNTER=$((LOOP_COUNTER+1))
	if [ ! -f $CACHE_TMP_FILE ] ; then
    if [ $(( $LOOP_COUNTER % 10)) -eq 0 ] ; then
      echo -n "."
    fi
    STOP_TIMEOUT=$((STOP_TIMEOUT-1))
    if [ $STOP_TIMEOUT -le 0 ] ; then
      echo  "."
      echo -n "INFO  broadcast - Terminating Packet Capture Pre-Processor "
      kill -9  $(ps -ef | grep pcpuser | grep "pcp-pec[t]" | grep -v grep | awk '{print $2}' | tail -n 1) > /dev/null 2>&1
      echo  "."
    fi
  fi  
  
  if [ -f $CACHE_TMP_FILE ] ; then
    if [ $WRITING_CACHE -eq 0 ] ; then
      echo  "."
      echo -n "INFO  broadcast - Writing Cache...this could take a while "
      WRITING_CACHE=1
    fi
    if [ $(( $LOOP_COUNTER % 10)) -eq 0 ] ; then
      echo  -n "."
    fi
  fi
done


if [[ -s  $PCP_TTY_TERMINAL  && -w $PCP_TTY_TERMINAL ]]; then
  if [ -e  $(cat $PCP_TTY_TERMINAL) ]; then
     TTY_OWNER=$(ls -l $(cat $PCP_TTY_TERMINAL)|awk '{print $3}');
     if [[ "$USER" == "$TTY_OWNER" ]]; then
        echo -n "$PCP_PROMPT ">$(cat $PCP_TTY_TERMINAL) 2>&1
     fi
  fi
fi
echo ""
echo "INFO  broadcast - Packet Capture Pre-Processor stopped."  
exit 0
