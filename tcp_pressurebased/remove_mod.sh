sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod tcp_nice
#insmod tcp_aluminum.ko alpha=1500
sysctl net.ipv4.tcp_congestion_control
#dmesg -c

lsmod|grep nice
