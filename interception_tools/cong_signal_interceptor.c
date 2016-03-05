#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <glib.h>

//SOL_TCP is just the protocol number.
//TCP options extracted from http://lxr.free-electrons.com/source/include/uapi/linux/tcp.h
#define SOL_TCP 6
#define TCP_CAPACITY_SIGNAL 29
#define TCP_CONGESTION 13

#define SIGNAL_LISTEN_PORT 9000

//#define DEBUG
 
typedef int (*orig_connect_f_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*orig_accept_f_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*orig_close_f_type)(int fd);

static int signalfd;
static pthread_t signalthread;
static int keep_listening;
static GArray *socket_array;
static GMutex socket_array_mutex;
 
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
#ifdef DEBUG
	printf("Intercepted a connect call!\n");
#endif
	orig_connect_f_type orig_connect;
	orig_connect = (orig_connect_f_type)dlsym(RTLD_NEXT,"connect");
	int retval = orig_connect(sockfd, addr, addrlen);

	if (retval>=0) {
		//sockfd is the descriptor of the newly connected socket
		g_mutex_lock(&socket_array_mutex);
		g_array_append_val(socket_array, sockfd);
		g_mutex_unlock(&socket_array_mutex);

//		int signal_value = 1;
//		socklen_t len = sizeof(signal_value);
//		setsockopt(sockfd, SOL_TCP, TCP_CAPACITY_SIGNAL, &signal_value, len);
	}
	
	return retval;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
#ifdef DEBUG
	printf("Intercepted an accept call!\n");
#endif
	orig_accept_f_type orig_accept;
	orig_accept = (orig_accept_f_type)dlsym(RTLD_NEXT,"accept");
	int retval = orig_accept(sockfd, addr, addrlen);

	if (retval>=0) {
		//retval is the descriptor of the newly accepted socket	
		g_mutex_lock(&socket_array_mutex);
		g_array_append_val(socket_array, retval);
		g_mutex_unlock(&socket_array_mutex);

//		int signal_value = 1;
//		socklen_t len = sizeof(signal_value);
//		setsockopt(retval, SOL_TCP, TCP_CAPACITY_SIGNAL, &signal_value, len);
	}
	
	return retval;
}

int close(int fd)
{
#ifdef DEBUG
	printf("Intercepted a close call!\n");
#endif
	orig_close_f_type orig_close;
	orig_close = (orig_close_f_type)dlsym(RTLD_NEXT,"close");
	int retval = orig_close(fd);

	if (!retval) 
	{
		//If the close was successful, check if this fd is a socket we're tracking
		//and remove it from the socket_array if it is.
		g_mutex_lock(&socket_array_mutex);
		int index = -1, i;
		for(i=0; i<socket_array->len; i++) {
			if (g_array_index(socket_array, int, i) == fd) {
				index = i;
				break;
			}
		}
		if (index != -1) {
			g_array_remove_index(socket_array, index);
		}
		g_mutex_unlock(&socket_array_mutex);
	}
	
	return retval;
}

void *signal_listener_entry(void *param)
{
	#define BUFSIZE 256
	int sockfd = *((int *) param);
	char rcv_buf[BUFSIZE];
	int rcvlen;
	struct sockaddr_in remaddr;
	socklen_t addrlen;
	
	
	
	int signal_value = 1;
	socklen_t len = sizeof(signal_value);

	while (keep_listening) {
		rcvlen = recvfrom(sockfd, rcv_buf, BUFSIZE, 0, (struct sockaddr *) &remaddr, &addrlen);
	
		if (rcvlen > 0 && rcv_buf[0] == 'a') {
			g_mutex_lock(&socket_array_mutex);
			int index = -1, i;
			for(i=0; i<socket_array->len; i++) {
				setsockopt(g_array_index(socket_array, int, i),
					 SOL_TCP, TCP_CAPACITY_SIGNAL, &signal_value, len);
				
			}
			g_mutex_unlock(&socket_array_mutex);
		}
	}	
	return;	
}


__attribute__((constructor)) void init(void) 
{
	signalfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (signalfd < 0) {
		printf("ERROR: Capacity signal interceptor failed to initialize UDP socket for capacity signal.\n");
		return;
	}

	struct sockaddr_in myaddr;
	memset((char *) &myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SIGNAL_LISTEN_PORT);

	if (bind(signalfd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		printf("ERROR: Capacity signal interceptor failed to bind UDP socket for capacity signal.\n");
		return;
	}

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;
	if (setsockopt(signalfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
		printf("ERROR: Capacity signal interceptor failed to set RCVTIMEOUT for UDP socket for capacity signal.\n");
		return;
		
	}


	socket_array = g_array_new(FALSE, FALSE, sizeof(int));
	g_mutex_init(&socket_array_mutex);

	keep_listening = 1;
	if(pthread_create(&signalthread, NULL, signal_listener_entry, &signalfd)) {
		printf("ERROR: Capacity signal interceptor failed to start listener thread.\n");
		return;
	}

	
	printf("CAPACITY SIGNAL INTERCEPTOR LOADED: Listening for signals on port %d.\n", SIGNAL_LISTEN_PORT);	
}


__attribute__((destructor)) void cleanup(void)
{
	keep_listening = 0;
	if (signalthread) 
		pthread_join(signalthread, NULL);
	
	if(signalfd > 0)
		close(signalfd);
	
	g_array_free(socket_array, TRUE);
	g_mutex_clear(&socket_array_mutex);
} 
