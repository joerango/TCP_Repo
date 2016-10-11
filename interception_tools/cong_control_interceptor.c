#define _GNU_SOURCE
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

//SOL_TCP is just the protocol number.
//TCP options extracted from http://lxr.free-electrons.com/source/include/uapi/linux/tcp.h
#define SOL_TCP 6
#define TCP_CAPACITY_SIGNAL 29
#define TCP_CONGESTION 13

#define DEBUG
 
typedef int (*orig_connect_f_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*orig_accept_f_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

static char cc_value[256];
static socklen_t cc_len;
 
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
#ifdef DEBUG
	printf("Intercepted a connect call!\n");
#endif
	orig_connect_f_type orig_connect;
	orig_connect = (orig_connect_f_type)dlsym(RTLD_NEXT,"connect");
	int retval = orig_connect(sockfd, addr, addrlen);

	if (!retval) {
		if(setsockopt(retval, SOL_TCP, TCP_CONGESTION, cc_value, cc_len) != 0)
			printk("Failed to set CC module!!\n");
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

	if (retval>0) {
		if(setsockopt(retval, SOL_TCP, TCP_CONGESTION, cc_value, cc_len) != 0)
			printk("Failed to set CC module!!\n");
	}
	
	return retval;

}



__attribute__((constructor)) void init(void) 
{
	FILE *conf_file;
	conf_file = fopen("cc.val", "r");		
	fscanf(conf_file, "%s", cc_value);
	
	cc_len = strlen(cc_value);
	printf("CONGESTION CONTROL INTERCEPTOR LOADED: '%s' will be used.\n", cc_value);	
}
