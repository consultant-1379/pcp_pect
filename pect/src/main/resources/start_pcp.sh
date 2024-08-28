#!/bin/bash
# --------------------------------------------------------------------------------------------
# Packet Capture Pre-Processor
#
# Usage:
#
#       ./start_pcp.sh
#
#	    exit 0 for success
#	    exit 1 for error starting PCP
#
#       Author: Luke Potter - elukpot
#
#       Date: 18/06/13
#
#       Description:
#           This script starts an instance of Packet Capture Pre-processor.
#
# --------------------------------------------------------------------------------------------
# Copyright (c) 1999 - 2013 AB Ericsson Oy  All rights reserved.
# --------------------------------------------------------------------------------------------
# Version 1.4
# Version 1.5  Updated to read cache access time, to delay printing prompt until cache read.
# Version 1.6  Updated to ensure PCP is not started after JUMP; and not to loop forever wating for cache.
# Version 1.7  Updated to use uptime to determine server last reboot time;.
# Version 1.8  Added check to see if PCP started before "Reading Cache" section
# Version 1.9  Added wait for PCP to start before checking for errors 
# --------------------------------------------------------------------------------------------

PCP_HOME=/opt/ericsson/pcp/pect/pect
TIMEOUUT=600
START_NOT_ALLOWED_TIME=10

# ----------------------------------------------------------------------
# Main start here
# ----------------------------------------------------------------------
# if this is a reboot of the server; dont restart pcp
#TIME_SINCE_REBOOT=$(( $(date +%s) -  $(stat --printf='%Y' /proc/1) ))
#TIME_SINCE_REBOOT=$(( $(date +%s) - $(date --date "$(who -b |awk '{print $3" "$4}')" +%s) ))
TIME_SINCE_REBOOT_TEST=$(uptime|awk -F'[u]' '{print $2}')
TIME_SINCE_REBOOT=$(uptime|awk '{print $3}')


# UPTIME FORMAT = 16:11:21 up 5 days,  1:44,  1 user,  load average: 0.00, 0.00, 0.00
# Hours has a format of hh:mm; If ":" present, then server up greater than 60 mins
# if uptime > 24 hours then "days" will be present

if [[ ! "$TIME_SINCE_REBOOT_TEST" =~ "days" ]]; then
    if [[ ! "$TIME_SINCE_REBOOT_TEST" =~ ":" ]]; then  
        if [ $TIME_SINCE_REBOOT -le $START_NOT_ALLOWED_TIME ]; then
            echo "INFO broadcast - Packet Capture Pre-processor can be started $(( $START_NOT_ALLOWED_TIME +1)) minutes after reboot (currently $TIME_SINCE_REBOOT since reboot); Start manually as per the PCP SAG."
            exit 1
        fi
    fi
fi

# This script finds the PCP server's processes and starts them.
FILE_WRITER_LOG="/var/log/ericsson/pcp/file_writer.log"

cd $PCP_HOME

# get the prompt for pcp-monitor
if [[ -s $PCP_HOME/pcp_prompt && -w $PCP_HOME/pcp_prompt ]]; then
  expPS1=$(echo xyzzyplughtwisty | bash -i 2>&1 | grep xyzzyplughtwisty | head -1| sed 's/xyzzyplughtwisty//g')
  expPS1="${expPS1%"${expPS1##*[![:space:]]}"}"; # remove trailing whitespace characters.. Will add one on divert to TTY.
  echo -n "$expPS1" >$PCP_HOME/pcp_prompt
  chmod 777 $PCP_HOME/pcp_prompt
fi

#Add PCP Monitoring to cron
./pcp-cronUpdate add_monitor

#file_writer log is accessed  only after cache is read
if [ -f $FILE_WRITER_LOG ] ; then
  FIRST_ACCESS_TIME=$(stat -c "%Y" $FILE_WRITER_LOG)
else
  FIRST_ACCESS_TIME=0
fi

#Start PCP
$PCP_HOME/pcp-pect -properties $PCP_HOME/properties.xml &


echo "INFO  broadcast - Waiting for Packet Capture Pre-processor to Start "
sleep 10


# delay the script from finishing to allow pcp time to start
while [ ! -f $FILE_WRITER_LOG ] 
do 
  sleep 1
done


#check if PCP is running; If it is not EXIT; If it is check the cache is loading
STATUS=$(ps -ef |grep "pcp-pec[t]" | wc -l)
if [ $STATUS -eq 0 ]
then
        echo "FATAL broadcast - Failed to start Packet Capture Pre-processor."
    exit 1
fi


#If file_writer log modification time is zero, then it was not existant before; so check it now;
if [ $FIRST_ACCESS_TIME -eq 0 ] ; then
  FIRST_ACCESS_TIME=$(stat -c "%Y" $FILE_WRITER_LOG)
fi    
sleep 5 
echo -n "INFO  broadcast - Reading Cache "

# check file_writer log modified time; It will be first modified after cache is written
# use this as a trigger to end the program
if [ -f $FILE_WRITER_LOG ] ; then
    COUNT=0
   
    LAST_ACCESS_TIME=$(stat -c "%Y" $FILE_WRITER_LOG)
    
    
    while [ $LAST_ACCESS_TIME -eq $FIRST_ACCESS_TIME ] 
    do
      sleep 1
      COUNT=$((COUNT+1))
      LAST_ACCESS_TIME=$(stat -c "%Y" $FILE_WRITER_LOG)
      if [ $(( $COUNT % 5)) -eq 0 ] ; then
        echo -n "."
      fi
      if [ $COUNT  -gt $TIMEOUUT ] ; then
        echo -n ".timeout"
        break
      fi
    done
    echo "."
    sleep 10
fi



#Check if it is running
STATUS=$(ps -ef |grep "pcp-pec[t]" | wc -l)
if [ $STATUS -eq 0 ]
then
	echo "FATAL broadcast - Failed to start Packet Capture Pre-processor."
    exit 1
fi

#echo ""

exit 0
