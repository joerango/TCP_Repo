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

MODULE_AUTHOR("Stephen Hemminger <shemminger@linux-foundation.org>");
MODULE_DESCRIPTION("TCP cwnd snooper");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");

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

static const char procname[] = "tcpprobe";
static const char rxmit_procname[] = "tcpprobe_retransmit";

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

struct tcp_retransmit_log {
	ktime_t tstamp;
	u32	seqno;
	char	type;
	union {
		struct sockaddr		raw;
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	}	src, dst;
};

static struct {
	spinlock_t	lock;
	wait_queue_head_t wait;
	ktime_t		start;
	u32		lastcwnd;

	unsigned long	head, tail;
	struct tcp_log	*log;
} tcp_probe;

static struct {
	spinlock_t 	  	lock;
	wait_queue_head_t 	wait;
	ktime_t 	  	start;
	
	unsigned long 	  	head, tail;
	struct tcp_retransmit_log  	*log;
} tcp_retransmit_probe;
	


static inline int tcp_probe_used(void)
{
	return (tcp_probe.head - tcp_probe.tail) & (bufsize - 1);
}

static inline int tcp_probe_avail(void)
{
	return bufsize - tcp_probe_used() - 1;
}

static inline int tcp_retransmit_probe_used(void)
{
	
	return (tcp_retransmit_probe.head - tcp_retransmit_probe.tail) & (RETRANSMIT_BUFSIZE - 1);
}

static inline int tcp_retransmit_probe_avail(void)
{
	return RETRANSMIT_BUFSIZE - tcp_retransmit_probe_used() - 1;
}

#define tcp_probe_copy_fl_to_si4(inet, si4, mem)		\
	do {							\
		si4.sin_family = AF_INET;			\
		si4.sin_port = inet->inet_##mem##port;		\
		si4.sin_addr.s_addr = inet->inet_##mem##addr;	\
	} while (0)						\


/*
 * Hook inserted to be called before each receive packet.
 * Note: arguments must match tcp_rcv_established()!
 */
static void jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
				 const struct tcphdr *th, unsigned int len)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	const struct skeleton *w = inet_csk_ca(sk);

	/* Only update if port or skb mark matches */
	if (((port == 0 && fwmark == 0) ||
	     ntohs(inet->inet_dport) == port ||
	     ntohs(inet->inet_sport) == port ||
	     (fwmark > 0 && skb->mark == fwmark)) &&
	    (full || tp->snd_cwnd != tcp_probe.lastcwnd)) {

		spin_lock(&tcp_probe.lock);
		/* If log fills, just silently drop */
		if (tcp_probe_avail() > 1) {
			struct tcp_log *p = tcp_probe.log + tcp_probe.head;

			p->tstamp = ktime_get();
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

				p->dst.v6.sin6_family = AF_INET6;
				p->dst.v6.sin6_port = inet->inet_dport;
				p->dst.v6.sin6_addr = sk->sk_v6_daddr;
#endif
				break;
			default:
				BUG();
			}

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

			tcp_probe.head = (tcp_probe.head + 1) & (bufsize - 1);
		}
		tcp_probe.lastcwnd = tp->snd_cwnd;
		spin_unlock(&tcp_probe.lock);

		wake_up(&tcp_probe.wait);
	}

	jprobe_return();
}


static bool is_spurious_retransmission(struct tcp_sock *tp, int flag)

{

	//FLAG_ORIG_SACK_ACKED=0x200

	

	//Full condition used in the kernel to judge a retransmission was spurious. start in tcp_process_loss and follow the if statements all the way down until before()

	return ((flag & FLAG_ORIG_SACK_ACKED) || 

	(tp->undo_marker && (!tp->undo_retrans ||

	(!tp->retrans_stamp || (tp->rx_opt.saw_tstamp &&

	tp->rx_opt.rcv_tsecr &&

	((tp->rx_opt.rcv_tsecr - tp->retrans_stamp)<0))))));

}


/*
 * Hook inserted to be called before a loss is handled (after RTO).
 * Note: arguments must match tcp_process_loss()!
 */

static void jtcp_process_loss(struct sock *sk, int flag, bool is_dupack)

{

	struct tcp_sock *tp = tcp_sk(sk);

	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_retransmit_log *p; 
	pr_info("jtcp_process_loss\n");	

	if ((ntohs(inet->inet_dport) == port ||
	     ntohs(inet->inet_sport) == port)) {
		spin_lock(&tcp_retransmit_probe.lock);

		p = tcp_retransmit_probe.log + tcp_retransmit_probe.head;
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

			p->dst.v6.sin6_family = AF_INET6;
			p->dst.v6.sin6_port = inet->inet_dport;
			p->dst.v6.sin6_addr = sk->sk_v6_daddr;
#endif
			break;
		default:
			BUG();
		}
	
		if (tp->frto){

			//pr_info("tcp_process_loss called with frto enabled for a matching socket.\n");
			
			if(tcp_retransmit_probe_avail() > 1) {//There is available buffer to store the log.
				if (is_spurious_retransmission(tp,flag)) { 

				

					p->tstamp=ktime_get();

					p->seqno=tp->lost_retrans_low;

					p->type='S';

					

					//pr_info("FRTO decided spurious.\n");

				}

				else{

				

					p->tstamp=ktime_get();

					p->seqno=tp->lost_retrans_low;

					p->type='U';

	

					//pr_info("FRTO decided NOT spurious.\n");

				}

			}
			else{
				//pr_info("No buffer space available to record this tcp loss event.\n");
			}
		}
		else{
	
			p->tstamp=ktime_get();

			p->seqno=tp->lost_retrans_low;

			p->type='D';

			

			//pr_info("FRTO didn't handle this loss.\n");

		}
		tcp_retransmit_probe.head = (tcp_retransmit_probe.head + 1) & (RETRANSMIT_BUFSIZE - 1);
		//pr_info("Head is %lu\n",tcp_retransmit_probe.head);

		spin_unlock(&tcp_retransmit_probe.lock);
		wake_up(&tcp_retransmit_probe.wait);

	}
	jprobe_return();
}

static int jtcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	const struct inet_sock *inet = inet_sk(sk);

	if (ntohs(inet->inet_dport) == port ||
	     ntohs(inet->inet_sport) == port) {
		//pr_info("tcp_retransmit_skb called for a matching socket.\n");


		spin_lock(&tcp_retransmit_probe.lock);

		if(tcp_retransmit_probe_avail() > 1) {//There is available buffer to store the log. 
			struct tcp_retransmit_log *p = tcp_retransmit_probe.log + tcp_retransmit_probe.head;
			p->tstamp = ktime_get();
			p->seqno=TCP_SKB_CB(skb)->seq;
			p->type='R';
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

				p->dst.v6.sin6_family = AF_INET6;
				p->dst.v6.sin6_port = inet->inet_dport;
				p->dst.v6.sin6_addr = sk->sk_v6_daddr;
#endif
				break;
			default:
				BUG();
			}
		
			tcp_retransmit_probe.head = (tcp_retransmit_probe.head + 1) & (RETRANSMIT_BUFSIZE - 1);
			//pr_info("Head is %lu\n",tcp_retransmit_probe.head);
		}
		spin_unlock(&tcp_retransmit_probe.lock);
		wake_up(&tcp_retransmit_probe.wait);
	}
	jprobe_return();
	return 0;
}

static void jtcp_enter_loss(struct sock *sk, int how)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);
	
	if (ntohs(inet->inet_dport) == port ||
	     ntohs(inet->inet_sport) == port) {
		//pr_info("tcp_enter_loss called for a matching socket.\n");


		spin_lock(&tcp_retransmit_probe.lock);

		if(tcp_retransmit_probe_avail() > 1) {//There is available buffer to store the log. 
			struct tcp_retransmit_log *p = tcp_retransmit_probe.log + tcp_retransmit_probe.head;
			p->tstamp = ktime_get();
			p->seqno=tp->snd_una;
			p->type='T';
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

				p->dst.v6.sin6_family = AF_INET6;
				p->dst.v6.sin6_port = inet->inet_dport;
				p->dst.v6.sin6_addr = sk->sk_v6_daddr;
#endif
				break;
			default:
				BUG();
			}
	
			tcp_retransmit_probe.head = (tcp_retransmit_probe.head + 1) & (RETRANSMIT_BUFSIZE - 1);
			//pr_info("Head is %lu\n",tcp_retransmit_probe.head);
		}
		spin_unlock(&tcp_retransmit_probe.lock);
		wake_up(&tcp_retransmit_probe.wait);
	}
	jprobe_return();

}
static struct jprobe tcp_jprobe = {
	.kp = {
		.symbol_name	= "tcp_rcv_established",
	},
	.entry	= jtcp_rcv_established,
};


static struct jprobe tcp_retransmit_jprobe = {
	.kp = {
		.symbol_name = "tcp_process_loss",
	},
	.entry = jtcp_process_loss,
};

static struct jprobe tcp_retransmit_jprobe2 = {
	.kp = {
		.symbol_name = "tcp_retransmit_skb",
	},
	.entry = jtcp_retransmit_skb,
};

static struct jprobe tcp_retransmit_jprobe3 = {
	.kp = {
		.symbol_name = "tcp_enter_loss",
	},
	.entry = jtcp_enter_loss,
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
			"%lu.%09lu %pISpc %pISpc %d %#x %#x %u %u %u %u %u %u %u %u %d %c\n",
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

static int tcpprobe_retransmit_open(struct inode *inode, struct file *file)
{
	/* Reset (empty) log */
	spin_lock_bh(&tcp_retransmit_probe.lock);
	tcp_retransmit_probe.head = tcp_retransmit_probe.tail = 0;
	spin_unlock_bh(&tcp_retransmit_probe.lock);

	return 0;
}

static int tcpprobe_retransmit_sprint(char *tbuf, int n)
{
	const struct tcp_retransmit_log *p
		= tcp_retransmit_probe.log + tcp_retransmit_probe.tail;
	struct timespec tv //print absolute kernel time to be able to sync different server logs.
		= ktime_to_timespec(p->tstamp);
		//= ktime_to_timespec(ktime_sub(p->tstamp, tcp_retransmit_probe.start));

	int cnt= scnprintf(tbuf, n,
			"%lu.%09lu %pISpc %pISpc %u %c\n",
			(unsigned long) tv.tv_sec,
			(unsigned long) tv.tv_nsec,
			&p->src, &p->dst,
			p->seqno, p->type);
	return cnt;
}

static ssize_t tcpprobe_retransmit_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	int error = 0;
	size_t cnt = 0;
	
	int eventbuf=2;
	
	if (!buf)
		return -EINVAL;

	while ((eventbuf>0) && (cnt < len)) {
		char tbuf[256];
		int width;

		/* Wait for data in buffer */
		error = wait_event_interruptible(tcp_retransmit_probe.wait,
						 tcp_retransmit_probe_used() > 0);
		if (error)
			break;

		spin_lock_bh(&tcp_retransmit_probe.lock);
		if (tcp_retransmit_probe.head == tcp_retransmit_probe.tail) {
			/* multiple readers race? */
			spin_unlock_bh(&tcp_retransmit_probe.lock);
			continue;
		}

		width = tcpprobe_retransmit_sprint(tbuf, sizeof(tbuf));

		if (cnt + width < len)
			tcp_retransmit_probe.tail = (tcp_retransmit_probe.tail + 1) & (RETRANSMIT_BUFSIZE - 1);
			//pr_info("Tail is %lu\n",tcp_retransmit_probe.tail);


		spin_unlock_bh(&tcp_retransmit_probe.lock);
		
		//pr_info("Will write %s. cnt=%u len=%u width=%u",tbuf,cnt,len,width);
		/* if record greater than space available
		   return partial buffer (so far) */
		if (cnt + width >= len)
			break;

		if (copy_to_user(buf + cnt, tbuf, width))
			return -EFAULT;
		eventbuf--;
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

static const struct file_operations tcpprobe_retransmit_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tcpprobe_retransmit_open,
	.read    = tcpprobe_retransmit_read,
	.llseek  = noop_llseek,
};

static __init int tcpprobe_init(void)
{
	int ret = -ENOMEM;

	/* Warning: if the function signature of tcp_rcv_established
	 * or tcp_process_loss,
	 * has been changed, you also have to change the signature of
	 * jtcp_rcv_established or tcp_process_loss (respectively),
	 * otherwise you end up right here!
	 */
	BUILD_BUG_ON(__same_type(tcp_rcv_established,
				 jtcp_rcv_established) == 0);
	BUILD_BUG_ON(__same_type(tcp_process_loss,
				 jtcp_process_loss) == 0);
	BUILD_BUG_ON(__same_type(tcp_retransmit_skb,
				 jtcp_retransmit_skb) == 0);
	BUILD_BUG_ON(__same_type(tcp_enter_loss,
				 jtcp_enter_loss) == 0);

	init_waitqueue_head(&tcp_probe.wait);
	spin_lock_init(&tcp_probe.lock);

	init_waitqueue_head(&tcp_retransmit_probe.wait);
	spin_lock_init(&tcp_retransmit_probe.lock);

	if (bufsize == 0)
		return -EINVAL;

	bufsize = roundup_pow_of_two(bufsize);
	tcp_probe.log = kcalloc(bufsize, sizeof(struct tcp_log), GFP_KERNEL);
	if (!tcp_probe.log)
		goto err0;
	
	tcp_retransmit_probe.log = kcalloc(RETRANSMIT_BUFSIZE, sizeof(struct tcp_retransmit_log), GFP_KERNEL);
	if (!tcp_retransmit_probe.log)
		goto err0;


	//Initialize timers for both log files to the current kernel time.
	spin_lock_bh(&tcp_probe.lock);
	spin_lock_bh(&tcp_retransmit_probe.lock);

	tcp_probe.start = tcp_retransmit_probe.start = ktime_get();
	
	spin_unlock_bh(&tcp_retransmit_probe.lock);
	spin_unlock_bh(&tcp_probe.lock);

	
	//Proc entry for packet by packet information.
	if (!proc_create(procname, S_IRUSR, init_net.proc_net, &tcpprobe_fops))
		goto err0;

	//Proc entry for reporting retransmission/loss events.
	if(!proc_create(rxmit_procname, S_IRUSR, init_net.proc_net, &tcpprobe_retransmit_fops))
		goto err0;

	ret = register_jprobe(&tcp_jprobe);
	if (ret)
		goto err1;
	ret = register_jprobe(&tcp_retransmit_jprobe);
	if (ret)
		goto err1;
	ret = register_jprobe(&tcp_retransmit_jprobe2);
	if (ret)
		goto err1;
	ret = register_jprobe(&tcp_retransmit_jprobe3);
	if (ret)
		goto err1;

	pr_info("Joseph's TCP Probe (DEV) with BW Estimation Support loaded. 4 probes registered (port=%d/fwmark=%u) bufsize=%u\n",port, fwmark, bufsize);
	return 0;
 err1:
	remove_proc_entry(procname, init_net.proc_net);
	remove_proc_entry(rxmit_procname, init_net.proc_net);
 err0:
	kfree(tcp_probe.log);
	kfree(tcp_retransmit_probe.log);
	return ret;
}
module_init(tcpprobe_init);

static __exit void tcpprobe_exit(void)
{
	remove_proc_entry(procname, init_net.proc_net);
	remove_proc_entry(rxmit_procname, init_net.proc_net);
	unregister_jprobe(&tcp_jprobe);
	unregister_jprobe(&tcp_retransmit_jprobe);
	unregister_jprobe(&tcp_retransmit_jprobe2);
	unregister_jprobe(&tcp_retransmit_jprobe3);
	kfree(tcp_probe.log);
	kfree(tcp_retransmit_probe.log);
}
module_exit(tcpprobe_exit);
