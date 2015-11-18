sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod tcp_nice
insmod tcp_nice.ko
sysctl -w net.ipv4.tcp_congestion_control=nice
#dmesg -c

lsmod|grep nice
