sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod tcp_mycubic
insmod tcp_mycubic.ko
sysctl -w net.ipv4.tcp_congestion_control=mycubic
#dmesg -c

lsmod|grep mycubic
