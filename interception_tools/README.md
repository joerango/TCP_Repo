# TCP Interception Tools
This set of tools produces shared libraries that can be used to intercept TCP functions called by an application to manipulate various properties of TCP.

### Congestion Control Interceptor
Changes the congestion control alogrithm for any newly connected or accepted socket to the congestion control algorithm specified in the file cc.val. The value in cc.val must be one of the congestion control algorithms returned by 
```sh
$ sysctl net.ipv4.tcp_available_congestion_control
```
Usage example. The following command will cause any connections started/accepted by iperf to use the congestion control module specified in cc.val
```sh
$ LD_PRELOAD=$PWD/cong_control_interceptor.so iperf -s -i 1
```

