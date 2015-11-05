sysctl -w net.ipv4.tcp_congestion_control=cubic
rmmod tcp_myreno
insmod tcp_myreno.ko
sysctl -w net.ipv4.tcp_congestion_control=myreno
#dmesg -c

lsmod|grep myreno
