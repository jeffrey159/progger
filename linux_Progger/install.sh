#!/bin/bash
#! TJChoi start
mac=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address)
machex=$( echo "$mac" | tr -d ':' )
sudo /sbin/insmod progger_trace.ko cpHostId=$machex
#! TJChoi end
#! sudo /sbin/insmod progger_trace.ko
