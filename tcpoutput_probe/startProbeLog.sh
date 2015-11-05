#!/bin/bash
cat /proc/net/tcpoutputprobe > probe.out &
PID1=$!
echo 'Probe activated. Press any key to stop.'
read -N 1 -s
kill $PID1
rmmod tcpoutput_probe
echo 'Stopped.'
