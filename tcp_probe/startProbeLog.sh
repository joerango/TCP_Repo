#!/bin/bash
cat /proc/net/tcpprobe > probe1.out &
PID1=$!
cat /proc/net/tcpprobe_retransmit > probe2.out &
PID2=$!
echo 'Probes activated. Press any key to stop.'
read -N 1 -s
kill $PID1
kill $PID2
rmmod tcp_probe
echo 'Stopped.'
