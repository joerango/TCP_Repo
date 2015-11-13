/*
 * tcpprobe - Observe the TCP flow with kprobes.
 *
 * The idea for this came from Werner Almesberger's umlsim
 * Copyright (C) 2004, Stephen Hemminger <shemminger@osdl.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <net/tcp.h>

#include <net/net_namespace.h>

MODULE_AUTHOR("Joseph D. Beshay <joseph.beshay@utdallas.edu>");
MODULE_DESCRIPTION("TCP Outgoing Packet Snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

static int port __read_mostly;
MODULE_PARM_DESC(port, "Port to match (0=all)");
module_param(port, int, 0);

static unsigned int bufsize __read_mostly = 4096;
MODULE_PARM_DESC(bufsize, "Log buffer size in packets (4096)");
module_param(bufsize, uint, 0);

static unsigned int fwmark __read_mostly;
MODULE_PARM_DESC(fwmark, "skb mark to match (0=no mark)");
module_param(fwmark, uint, 0);

static int full __read_mostly;
MODULE_PARM_DESC(full, "Full log (1=every ack packet received,  0=only cwnd changes)");
module_param(full, int, 0);

static const char procname[] = "tcpoutputprobe";

#define RETRANSMIT_BUFSIZE	256
#define FLAG_ORIG_SACK_ACKED	0x200

/* TCP Probe Appendix structure. For BW measurements. */
struct probeAppendix {
	char 	last_decision;
	u32	bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
	u32	bw_est;           /* bandwidth estimate */
};

/* TCP Congestion Avoidance skeleton structure */
struct skeleton {
	char	flag;
	struct probeAppendix *appendix;
};


struct tcp_log {
	ktime_t tstamp;
	union {
		struct sockaddr		raw;
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	}	src, dst;
	u16	length;
	u32	snd_nxt;
	u32	snd_una;
	u32	snd_wnd;
	u32	rcv_wnd;
	u32	snd_cwnd;
	u32	ssthresh;
	u32	srtt;
	u32	rto;
	u32	bw_est;
	u32 	packets_in_flight;
	int	pressure;
	char	last_decision;
};

static struct {
	spinlock_t	lock;
	wait_queue_head_t wait;
	ktime_t		start;
	u32		lastcwnd;

	unsigned long	head, tail;
	struct tcp_log	*log;
} tcp_probe;	


static inline int tcp_probe_used(void)
{
	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail(void)
{
	return bufsize - tcp_probe_used() - 1;
}

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)		\
	do {							\
		si4.sin_family = AF_INET;			\
		si4.sin_port = inet->inet_##mem##port;		\
		si4.sin_addr.s_addr = inet->inet_##mem##addr;	\
	} while (0)						\


/*
 * Populates the probe log entry with the information of the given tcp socket.
 * Does not log the tcp_probe circular list. You have to do this surround this function
 * with the lock and unlock. This is to allow further changes to the struct before unlocking
 */
static void populate_probe_log(struct tcp_log *p, struct sock *sk, struct sk_buff *skb)
{

	const struct tcp_sock *tp = tcp_sk(sk);
        const struct inet_sock *inet = inet_sk(sk);
	const struct skeleton *w = inet_csk_ca(sk);

	p->tstamp = ktime_get_real();
	switch (sk->sk_family) {
	case AF_INET:
		tcp_probe_copy_fl_to_si4(inet, p->src.v4, s);
		tcp_probe_copy_fl_to_si4(inet, p->dst.v4, d);
		break;
	case AF_INET6:
		memset(&p->src.v6, 0, sizeof(p->src.v6));
		memset(&p->dst.v6, 0, sizeof(p->dst.v6));
#if IS_ENABLED(CONFIG_IPV6)
		p->src.v6.sin6_family = AF_INET6;
		p->src.v6.sin6_port = inet->inet_sport;
		p->src.v6.sin6_addr = inet6_sk(sk)->saddr;

		p->dst.v6.sin6_family = AF_INET6; p->dst.v6.sin6_port = inet->inet_dport; p->dst.v6.sin6_addr = sk->sk_v6_daddr;
#endif
		break;
	default:
		BUG();
	}
	if (skb == NULL)
		p->length = 0;
	else
		p->length = skb->len;
	p->snd_nxt = tp->snd_nxt;
	p->snd_una = tp->snd_una;
	p->snd_cwnd = tp->snd_cwnd;
	p->packets_in_flight = tcp_packets_in_flight(tp);
	p->snd_wnd = tp->snd_wnd;
	p->rcv_wnd = tp->rcv_wnd;
	p->ssthresh = tcp_current_ssthresh(sk);
	p->srtt = tp->srtt_us >> 3;
	p->rto = jiffies_to_usecs((unsigned long)inet_csk(sk)->icsk_rto);
	p->bw_est = 0;
	p->pressure = tp->pressure;
	p->last_decision = 'Z';
	if(w->flag=='j'){
		p->bw_est= (HZ * (w->appendix)->bw_ns_est) >> 7; //Convert from bytes/jiffy to Kbps
		p->last_decision = (w->appendix)->last_decision;
	}
}

inline bool is_relevant_socket(struct sock *sk, struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
        const struct inet_sock *inet = inet_sk(sk);
	if (((port == 0 && fwmark == 0) ||
             ntohs(inet->inet_dport) == port ||
             ntohs(inet->inet_sport) == port ||
             (fwmark > 0 && skb != NULL && skb->mark == fwmark)) &&
            (full || tp->snd_cwnd != tcp_probe.lastcwnd))
		return true;
	else
		return false;
}

/*
 * From tcp_output.c file. For every outgoing TCP packet.
 */
static int jtcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
	                          gfp_t gfp_mask)
{
	const struct tcp_sock *tp = tcp_sk(sk);

        /* Only record log for relevant sockets. */
        if (is_relevant_socket(sk, skb)) {
                spin_lock(&tcp_probe.lock);
                /* If log fills, just silently drop */
                if (tcp_probe_avail() > 1) {
                        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			populate_probe_log(p, sk, skb);
			
                        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
                }
                tcp_probe.lastcwnd = tp->snd_cwnd;
                spin_unlock(&tcp_probe.lock);

                wake_up(&tcp_probe.wait);
        }

        jprobe_return();
	return 0;
}

// From tcp_output.c
static int jtcp_connect(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

        /* Only record log for relevant sockets. */
        if (is_relevant_socket(sk, NULL)) {
                spin_lock(&tcp_probe.lock);
                /* If log fills, just silently drop */
                if (tcp_probe_avail() > 1) {
                        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			populate_probe_log(p, sk, NULL);
			p->last_decision = '1';

                        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
                }
                tcp_probe.lastcwnd = tp->snd_cwnd;
                spin_unlock(&tcp_probe.lock);

                wake_up(&tcp_probe.wait);
        }

        jprobe_return();
	return 0;
}

// From tcp.c When close is called for a TCP socket
static void jtcp_close(struct sock *sk, long timeout)
{
	const struct tcp_sock *tp = tcp_sk(sk);

        /* Only record log for relevant sockets. */
        if (is_relevant_socket(sk, NULL)) {
                spin_lock(&tcp_probe.lock);
                /* If log fills, just silently drop */
                if (tcp_probe_avail() > 1) {
                        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			populate_probe_log(p, sk, NULL);
			p->last_decision = '2';

                        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
                }
                tcp_probe.lastcwnd = tp->snd_cwnd;
                spin_unlock(&tcp_probe.lock);

                wake_up(&tcp_probe.wait);
        }

        jprobe_return();
	return;
}

// From tcp.c When disconnect is called for a TCP socket
static int jtcp_disconnect(struct sock *sk, int flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);

        /* Only record log for relevant sockets. */
        if (is_relevant_socket(sk, NULL)) {
                spin_lock(&tcp_probe.lock);
                /* If log fills, just silently drop */
                if (tcp_probe_avail() > 1) {
                        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			populate_probe_log(p, sk, NULL);
			p->last_decision = '3';

                        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
                }
                tcp_probe.lastcwnd = tp->snd_cwnd;
                spin_unlock(&tcp_probe.lock);

                wake_up(&tcp_probe.wait);
        }

        jprobe_return();
	return 0;
}

// From tcp.c When shutdown is called for a TCP socket
static void jtcp_shutdown(struct sock *sk, int how)
{
	const struct tcp_sock *tp = tcp_sk(sk);

        /* Only record log for relevant sockets. */
        if (is_relevant_socket(sk, NULL)) {
                spin_lock(&tcp_probe.lock);
                /* If log fills, just silently drop */
                if (tcp_probe_avail() > 1) {
                        struct tcp_log *p = tcp_probe.log + tcp_probe.head;
			populate_probe_log(p, sk, NULL);
			p->last_decision = '4';

                        tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
                }
                tcp_probe.lastcwnd = tp->snd_cwnd;
                spin_unlock(&tcp_probe.lock);

                wake_up(&tcp_probe.wait);
        }

        jprobe_return();
}


static struct jprobe jprobe_transmit = {
	.kp = {
		.symbol_name	= "tcp_transmit_skb",
	},
	.entry	= jtcp_transmit_skb,
};

static struct jprobe jprobe_connect = {
	.kp = {
		.symbol_name	= "tcp_connect",
	},
	.entry	= jtcp_connect,
};

static struct jprobe jprobe_close = {
	.kp = {
		.symbol_name	= "tcp_close",
	},
	.entry	= jtcp_close,
};

static struct jprobe jprobe_disconnect = {
	.kp = {
		.symbol_name	= "tcp_disconnect",
	},
	.entry	= jtcp_disconnect,
};

static struct jprobe jprobe_shutdown = {
	.kp = {
		.symbol_name	= "tcp_shutdown",
	},
	.entry	= jtcp_shutdown,
};


static int tcpprobe_open(struct inode *inode, struct file *file)
{
	/* Reset (empty) log */
	spin_lock_bh(&tcp_probe.lock);
	tcp_probe.head = tcp_probe.tail = 0;
	spin_unlock_bh(&tcp_probe.lock);
	

	return 0;
}

static int tcpprobe_sprint(char *tbuf, int n)
{
	const struct tcp_log *p
		= tcp_probe.log + tcp_probe.tail;
	struct timespec tv //print absolute time to be able to sync with other servers.
		= ktime_to_timespec(p->tstamp);
		//= ktime_to_timespec(ktime_sub(p->tstamp, tcp_probe.start));

	return scnprintf(tbuf, n,
			"%lu.%09lu %pISpc %pISpc %d %#x %#x %u %u %u %u %u %u %u %u %u %c\n",
			(unsigned long) tv.tv_sec,
			(unsigned long) tv.tv_nsec,
			&p->src, &p->dst, p->length, p->snd_nxt, p->snd_una,
			p->snd_cwnd, p->ssthresh, p->snd_wnd, p->srtt, p->rcv_wnd, p->rto, p->bw_est, p->packets_in_flight, p->pressure, p->last_decision);
}

static ssize_t tcpprobe_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	int error = 0;
	size_t cnt = 0;

	if (!buf)
		return -EINVAL;

	while (cnt < len) {
		char tbuf[256];
		int width;

		/* Wait for data in buffer */
		error = wait_event_interruptible(tcp_probe.wait,
						 tcp_probe_used() > 0);
		if (error)
			break;

		spin_lock_bh(&tcp_probe.lock);
		if (tcp_probe.head == tcp_probe.tail) {
			/* multiple readers race? */
			spin_unlock_bh(&tcp_probe.lock);
			continue;
		}

		width = tcpprobe_sprint(tbuf, sizeof(tbuf));

		if (cnt + width < len)
			tcp_probe.tail = (tcp_probe.tail + 1) & (bufsize - 1);

		spin_unlock_bh(&tcp_probe.lock);

		/* if record greater than space available
		   return partial buffer (so far) */
		if (cnt + width >= len)
			break;

		if (copy_to_user(buf + cnt, tbuf, width))
			return -EFAULT;
		cnt += width;
	}

	return cnt == 0 ? error : cnt;
}

static const struct file_operations tcpprobe_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_open,
	.read    = tcpprobe_read,
	.llseek  = noop_llseek,
};

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;

	/* Warning: if the function signature of any of the probed functions
	 * has been changed, you also have to change the signature of
	 * the probe handlers (the functions starting with j),
	 * otherwise you end up right here!
	 */
	BUILD_BUG_ON(__same_type(tcp_transmit_skb,
				 jtcp_transmit_skb) == 0);
	BUILD_BUG_ON(__same_type(tcp_close,
                                 jtcp_close) == 0);
	BUILD_BUG_ON(__same_type(tcp_connect,
                                 jtcp_connect) == 0);
	BUILD_BUG_ON(__same_type(tcp_disconnect,
                                 jtcp_disconnect) == 0);
	BUILD_BUG_ON(__same_type(tcp_shutdown,
                                 jtcp_shutdown) == 0);

	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.lock);

	if (bufsize == 0)
		return -EINVAL;

	bufsize = roundup_pow_of_two(bufsize);
	tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log)
		goto err0;
	
	//Initialize timers for both log files to the current kernel time.
	spin_lock_bh(&tcp_probe.lock);

	tcp_probe.start = ktime_get();
	
	spin_unlock_bh(&tcp_probe.lock);

	
	//Proc entry for packet by packet information.
	if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcpprobe_fops))
		goto err0;

	ret = register_jprobe(&jprobe_transmit);
	if (ret)
		goto err1;
	ret = register_jprobe(&jprobe_connect);
	if (ret)
		goto err1;
	ret = register_jprobe(&jprobe_close);
	if (ret)
		goto err1;
	ret = register_jprobe(&jprobe_disconnect);
	if (ret)
		goto err1;
	ret = register_jprobe(&jprobe_shutdown);
	if (ret)
		goto err1;

	pr_info("Joseph's TCP Output Probe (DEV) with BW Estimation Support loaded. 5 probe registered (port=%d/fwmark=%u) bufsize=%u\n",port, fwmark, bufsize);
	return 0;
 err1:
	remove_proc_entry(procname, init_net.proc_net);
 err0:
	kfree(tcp_probe.log);
	return ret;
}
module_init(tcpprobe_init);

static __exit void tcpprobe_exit(void)
{
	remove_proc_entry(procname, init_net.proc_net);
	unregister_jprobe(&jprobe_transmit);
	unregister_jprobe(&jprobe_connect);
	unregister_jprobe(&jprobe_close);
	unregister_jprobe(&jprobe_disconnect);
	unregister_jprobe(&jprobe_shutdown);
	kfree(tcp_probe.log);
}
module_exit(tcpprobe_exit);
