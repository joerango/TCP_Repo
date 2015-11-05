#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#define PROBE_RTT_MIN   (HZ/20)	/* 50ms */
#define PROBE_INIT_RTT  (20*HZ)	/* maybe too conservative?! */

/* Struct to hold BW measurements for tcp_probe as well as any fields 
   that had to to be moved out of this congestion avoidance module's struct
   for the lack of space.
 */
struct probeAppendix {
	//Base Appendix Struct fields
	char 	last_decision;
	u32	bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
	u32	bw_est;           /* bandwidth estimate */

	//Bandwidth Estimation fields
	u32    rtt_win_sx;       /* here starts a new evaluation... */
        u32    bk;
        u32    snd_una;          /* used for evaluating the number of acked bytes */
        u32    cumul_ack;
        u32    accounted;
        u32    rtt;
        u8     first_ack;        /* flag which infers that this is the first ack */
};

/* BIC TCP Parameters */
struct tcpreno {
	char	flag;
	struct probeAppendix *appendix;
};

static void probe_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	if (rtt > 0)
		pa->rtt = usecs_to_jiffies(rtt);
}

static inline u32 probe_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

static void probe_filter(struct probeAppendix *pa, u32 delta)
{
	/* If the filter is empty fill it with the first sample of bandwidth  */
	if (pa->bw_ns_est == 0 && pa->bw_est == 0) {
		pa->bw_ns_est = pa->bk / delta;
		pa->bw_est = pa->bw_ns_est;
	} else {
		pa->bw_ns_est = probe_do_filter(pa->bw_ns_est, pa->bk / delta);
		pa->bw_est = probe_do_filter(pa->bw_est, pa->bw_ns_est);
	}
}

static void probe_update_window(struct sock *sk)
{
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	s32 delta = tcp_time_stamp - pa->rtt_win_sx;


	/* Initialize w->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and w->snd_una for the first
	 * bandwidth sample
	 */
	if (pa->first_ack) {
		pa->snd_una = tcp_sk(sk)->snd_una;
		pa->first_ack = 0;
	}

	/*
	 * See if a RTT-window has passed.
	 * Be careful since if RTT is less than
	 * 50ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was chosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obviously on a LAN we reasonably will always have
	 * right_bound = left_bound + WESTWOOD_RTT_MIN
	 */
	if (pa->rtt && delta > max_t(u32, pa->rtt, PROBE_RTT_MIN)) {
		probe_filter(pa, delta);

		pa->bk = 0;
		pa->rtt_win_sx = tcp_time_stamp;

	}
}

static inline void probe_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	probe_update_window(sk);

	pa->bk += tp->snd_una - pa->snd_una;
	pa->snd_una = tp->snd_una;
}

static inline u32 probe_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	pa->cumul_ack = tp->snd_una - pa->snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!pa->cumul_ack) {
		pa->accounted += tp->mss_cache;
		pa->cumul_ack = tp->mss_cache;
	}

	if (pa->cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
		if (pa->accounted >= pa->cumul_ack) {
			pa->accounted -= pa->cumul_ack;
			pa->cumul_ack = tp->mss_cache;
		} else {
			pa->cumul_ack -= pa->accounted;
			pa->accounted = 0;
		}
	}

	pa->snd_una = tp->snd_una;

	return pa->cumul_ack;
}



//BW Estimation functions added by Joseph. This code comes from Westwood.
static void tcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	switch (event) {
	case CA_EVENT_FAST_ACK:
		probe_fast_bw(sk);
		break;

	case CA_EVENT_SLOW_ACK:
		probe_update_window(sk);
		pa->bk += probe_acked_count(sk);
		break;

	default:
		/* don't care */
		break;
	}
}

static void myreno_init(struct sock *sk)
{
	struct tcpreno *ca = inet_csk_ca(sk);
	struct probeAppendix *pa;

	ca->flag = 'j';
	ca->appendix = kmalloc (sizeof(struct probeAppendix), GFP_KERNEL);

	if(!ca->appendix)
		printk("ERROR: Failed to allocate memory for probeAppendix struct in MyReno");
	
	pa = ca->appendix;	
	pa->last_decision = 'A';
	pa->bk = 0;
	pa->bw_ns_est = 0;
	pa->bw_est = 0;
	pa->accounted = 0;
	pa->cumul_ack = 0;
	pa->rtt_win_sx = tcp_time_stamp;
	pa->snd_una = tcp_sk(sk)->snd_una;
	pa->first_ack = 1;	
}

static void myreno_release(struct sock *sk)
{
	struct tcpreno *ca = inet_csk_ca(sk);
	kfree(ca->appendix);
}

	
static struct tcp_congestion_ops tcp_myreno __read_mostly = {
	.init		= myreno_init,
	.release	= myreno_release,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.cwnd_event	= tcp_cwnd_event,
	.pkts_acked     = probe_pkts_acked,
	.owner		= THIS_MODULE,
	.name		= "myreno",
};

static int __init tcp_myreno_register(void)
{
	BUILD_BUG_ON(sizeof(struct tcpreno) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_myreno);
}

static void __exit tcp_myreno_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_myreno);
}

module_init(tcp_myreno_register);
module_exit(tcp_myreno_unregister);

MODULE_AUTHOR("Joseph Beshay");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("JOSPEPH'S MODIFIED TCP RENO");
MODULE_VERSION("1988");
