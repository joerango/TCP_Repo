rmmod tcpoutput_probe
insmod tcpoutput_probe.ko full=1 port=$1
#dmesg -c
chmod 444 /proc/net/tcpoutputprobe
