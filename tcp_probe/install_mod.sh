rmmod tcp_probe
insmod tcp_probe.ko full=1 port=$1
#dmesg -c
chmod 444 /proc/net/tcpprobe
chmod 444 /proc/net/tcpprobe_retransmit
