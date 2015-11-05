sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod tcp_myvegas
insmod tcp_myvegas.ko
sysctl -w net.ipv4.tcp_congestion_control=myvegas
#dmesg -c

lsmod|grep myvegas
