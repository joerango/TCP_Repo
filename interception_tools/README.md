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

### Capacity Signal Interceptor
Tracks all open and accepted connections and listens on UDP port 9000 (hardcoded, for the time being) for capacity signals. A capacity signal is a single character 'a' in a UDP packet to port 9000. This signal will be passed on to all the tracked sockets using the TCP_SIGNAL_CAPACITY TCP socket option supported by my custom kernel.
