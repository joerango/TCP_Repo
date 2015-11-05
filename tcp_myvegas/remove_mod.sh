sysctl -w net.ipv4.tcp_congestion_control=cubic
sleep 1
rmmod tcp_myvegas
#insmod tcp_aluminum.ko alpha=1500
sysctl net.ipv4.tcp_congestion_control
#dmesg -c

lsmod|grep mycubic 
