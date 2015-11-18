#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
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
	u32    rtt;		 // This is in jiffies.
	u8     first_ack;        /* flag which infers that this is the first ack */
};


struct nice {
	char	flag;
	struct probeAppendix *appendix;
	u32	currentMode;	//0: loss-baed, 1:normal delay-based, 2: high priority delay-based

	u32 	beg_snd_nxt;
	u32	beg_snd_una;
	u32	beg_snd_cwnd;

	u32	delayBasedEnable;	//This is modeled after Vegas.	
	u32	cntRTT;
	u32	minRTT;			//In jiffies.
	u32	baseRTT;		//In jIffies
	u32	lastRTT;
	
	int alpha, beta, gamma;
};



static void probe_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct nice *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;
	
	//To avoid a zero rtt.
	u32 vrtt = usecs_to_jiffies(rtt + 1);
	
	pa->rtt = vrtt;
	
	if(vrtt < ca->baseRTT)
		ca->baseRTT = vrtt;


	ca->lastRTT = vrtt;
	ca->minRTT = min(ca->minRTT, vrtt);
	ca->cntRTT++;

	ca->alpha = 2;
	ca->beta = 4;
	ca->gamma = 1;
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
	struct nice *ca = inet_csk_ca(sk);
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
	struct nice *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	probe_update_window(sk);

	pa->bk += tp->snd_una - pa->snd_una;
	pa->snd_una = tp->snd_una;
}

static inline u32 probe_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct nice *ca = inet_csk_ca(sk);
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

static void delayBasedEnable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct nice *ca = inet_csk_ca(sk);

	/* Begin taking Vegas samples next time we send something. */
	ca->delayBasedEnable = 1;

	/* Set the beginning of the next send window. */
	ca->beg_snd_nxt = tp->snd_nxt;

	ca->cntRTT = 0;
	ca->minRTT = 0x7fffffff;
}

static inline void delayBasedDisable(struct sock *sk)
{
	struct nice *ca = inet_csk_ca(sk);

	ca->delayBasedEnable = 0;
}


//BW Estimation functions added by Joseph. This code comes from Westwood.
static void tcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct nice *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;

	switch (event) {
	case CA_EVENT_FAST_ACK:
		probe_fast_bw(sk);
		break;

	case CA_EVENT_SLOW_ACK:
		probe_update_window(sk);
		pa->bk += probe_acked_count(sk);
		break;
	case CA_EVENT_CWND_RESTART:
	case CA_EVENT_TX_START:
		delayBasedEnable(sk);
		ca->baseRTT=0x7fffffff;
		break;

	default:
		/* don't care */
		break;
	}
}


static void tcp_nice_state(struct sock *sk, u8 ca_state)
{
	if (ca_state == TCP_CA_Open)
		delayBasedEnable(sk);
	else
		delayBasedDisable(sk);
}


static u32 tcp_nice_ssthresh(struct sock *sk)
{
		const struct tcp_sock *tp = tcp_sk(sk);
		return max(tp->snd_cwnd >> 1U, 2U);
}

static void shortFlow_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct nice *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;
	u32 diff=0;

	if(ca->delayBasedEnable)
	{
		diff = tp->snd_cwnd * (ca->lastRTT - ca->baseRTT) / ca->baseRTT;
	}
	/* In "safe" area, increase */
	if (tp->snd_cwnd <= tp->snd_ssthresh && diff < 3 * ca->alpha)
	{
		u32 cwnd = tp->snd_cwnd + (acked);

		if (cwnd > tp->snd_ssthresh)
			cwnd = tp->snd_ssthresh + 1;
		
		tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
	}
	/* In dangerous area, increase slowly. */
	else
	{
		tcp_cong_avoid_ai(tp, tp->snd_cwnd);
	}
}

static void longFlow_cong_avoid(struct sock *sk, u32 ack, u32 acked,
				 u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct nice *ca = inet_csk_ca(sk);

	if (!ca->delayBasedEnable) {
		tcp_reno_cong_avoid(sk, ack, acked, in_flight);
		return;
	}

	if (after(ack, ca->beg_snd_nxt)) {
		/* Do the Vegas once-per-RTT cwnd adjustment. */

		/* Save the extent of the current window so we can use this
		 * at the end of the next RTT.
		 */
		ca->beg_snd_nxt  = tp->snd_nxt;

		/* We do the Vegas calculations only if we got enough RTT
		 * samples that we can be reasonably sure that we got
		 * at least one RTT sample that wasn't from a delayed ACK.
		 * If we only had 2 samples total,
		 * then that means we're getting only 1 ACK per RTT, which
		 * means they're almost certainly delayed ACKs.
		 * If  we have 3 samples, we should be OK.
		 */

		if (ca->cntRTT <= 2) {
			/* We don't have enough RTT samples to do the Vegas
			 * calculation, so we'll behave like Reno.
			 */
			tcp_reno_cong_avoid(sk, ack, acked, in_flight);
		} else {
			u32 rtt, diff;
			u64 target_cwnd;

			/* We have enough RTT samples, so, using the Vegas
			 * algorithm, we determine if we should increase or
			 * decrease cwnd, and by how much.
			 */

			/* Pluck out the RTT we are using for the Vegas
			 * calculations. This is the min RTT seen during the
			 * last RTT. Taking the min filters out the effects
			 * of delayed ACKs, at the cost of noticing congestion
			 * a bit later.
			 */
			rtt = ca->minRTT;

			/* Calculate the cwnd we should have, if we weren't
			 * going too fast.
			 *
			 * This is:
			 *     (actual rate in segments) * baseRTT
			 */
			target_cwnd = tp->snd_cwnd * ca->baseRTT / rtt;

			/* Calculate the difference between the window we had,
			 * and the window we would like to have. This quantity
			 * is the "Diff" from the Arizona Vegas papers.
			 */
			diff = tp->snd_cwnd * (rtt-ca->baseRTT) / ca->baseRTT;

			if (diff > ca->gamma && tp->snd_cwnd <= tp->snd_ssthresh) {
				/* Going too fast. Time to slow down
				 * and switch to congestion avoidance.
				 */

				/* Set cwnd to match the actual rate
				 * exactly:
				 *   cwnd = (actual rate) * baseRTT
				 * Then we add 1 because the integer
				 * truncation robs us of full link
				 * utilization.
				 */
				printk("Slowing down... my current targent_cwnd=%d snd_cwnd=%d\n",target_cwnd, tp->snd_cwnd);
				tp->snd_cwnd = min(tp->snd_cwnd, (u32)target_cwnd+1);
				tp->snd_ssthresh = min(tp->snd_ssthresh, tp->snd_cwnd-1);

			} else if (tp->snd_cwnd <= tp->snd_ssthresh) {
				/* Slow start.  */
				tcp_slow_start(tp, acked);
			} else {
				/* Congestion avoidance. */

				/* Figure out where we would like cwnd
				 * to be.
				 */
				if (diff > ca->beta) {
					/* The old window was too fast, so
					 * we slow down.
					 */
					tp->snd_cwnd--;
					tp->snd_ssthresh = min(tp->snd_ssthresh, tp->snd_cwnd-1);
				} else if (diff < ca->alpha) {
					/* We don't have enough extra packets
					 * in the network, so speed up.
					 */
					tp->snd_cwnd++;
				} else {
					/* Sending just as fast as we
					 * should be.
					 */
				}
			}

			if (tp->snd_cwnd < 2)
				tp->snd_cwnd = 2;
			else if (tp->snd_cwnd > tp->snd_cwnd_clamp)
				tp->snd_cwnd = tp->snd_cwnd_clamp;

			tp->snd_ssthresh = tcp_current_ssthresh(sk);
		}

		/* Wipe the slate clean for the next RTT. */
		ca->cntRTT = 0;
		ca->minRTT = 0x7fffffff;
	}
	/* Use normal slow start */
	else if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp, acked);

}


static void tcp_nice_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct nice *ca = inet_csk_ca(sk);
	struct probeAppendix *pa = ca->appendix;
	struct tcp_sock	*tp = tcp_sk(sk);
	pa->last_decision='-';

	if (!tcp_is_cwnd_limited(sk, in_flight))
	{
		pa->last_decision= '0';
		return;
	}

	// Three cases for cong control:
	// 		(1) Pressure <= 7: Connection operates in loss-based TCP mode. MODE 0
	//		(2) 7 < Pressure <=10: Connection operates in delay-based TCP mode with relatively high alpha, beta and gamma. MODE 1
	//		(3) Pressure > 10: Connection operates in delay-based TCP mode with low alpha, beta and gamma. MODE 2
	
	if(tp->pressure <= 7  && ca->currentMode != 0)
	{
		ca->currentMode = 0;
	}
	else if(tp->pressure > 7  && tp->pressure <= 10 && ca->currentMode != 1)
	{
		ca->currentMode = 1;
		ca->alpha = 2;
		ca->beta = 4;
		ca->gamma = 1;
	}
	else if(tp->pressure > 10 && ca->currentMode !=2)
	{
		ca->currentMode = 2;
		ca->alpha = 4;
		ca->beta = 6;
		ca->gamma = 3;
	}
	
	if (ca->currentMode ==0 )
	{
		pa->last_decision = 'A';
		shortFlow_cong_avoid(sk, ack, acked, in_flight);
	}
	else if(ca->currentMode == 1)
	{
		pa->last_decision = 'B';
		longFlow_cong_avoid(sk, ack, acked, in_flight);
	}
	else if(ca->currentMode == 2)
	{
		pa->last_decision = 'C';
		longFlow_cong_avoid(sk, ack, acked, in_flight);
	}
}


static void tcp_nice_init(struct sock *sk)
{
	
	struct nice *ca = inet_csk_ca(sk);
	
		
	//probeAppendix initialization
	ca->flag = 'j';
	ca->appendix = kmalloc (sizeof(struct probeAppendix), GFP_KERNEL);

	if(!ca->appendix)
		printk("ERROR: Failed to allocate memory for probeAppendix struct in Nice TCP. Kernel might crash very soon.");
	
	struct probeAppendix *pa = ca->appendix;	
	pa->last_decision = 'A';
	pa->bk = 0;
	pa->bw_ns_est = 0;
	pa->bw_est = 0;
	pa->accounted = 0;
	pa->cumul_ack = 0;
	pa->rtt_win_sx = tcp_time_stamp;
	pa->snd_una = tcp_sk(sk)->snd_una;
	pa->first_ack = 1;

	//Nice-specific initialization
	ca->baseRTT = 0x7fffffff;

	delayBasedEnable(sk);
}

static void tcp_nice_release(struct sock *sk)
{
	struct nice *ca = inet_csk_ca(sk);
	kfree(ca->appendix);
}
static struct tcp_congestion_ops tcp_nice __read_mostly = {
	.init		= tcp_nice_init,
	.release	= tcp_nice_release,
	.ssthresh	= tcp_nice_ssthresh,
	.cong_avoid	= tcp_nice_cong_avoid,
	.cwnd_event	= tcp_cwnd_event,
	.pkts_acked	= probe_pkts_acked,
	.set_state	= tcp_nice_state,

	.owner		= THIS_MODULE,
	.name		= "nice"
};

static int __init tcp_nice_register(void)
{
	BUILD_BUG_ON(sizeof(struct nice) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_nice);
}

static void __exit tcp_nice_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_nice);
}

module_init(tcp_nice_register);
module_exit(tcp_nice_unregister);

MODULE_AUTHOR("Joseph Beshay");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Nice TCP");
