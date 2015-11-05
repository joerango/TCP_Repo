/*
 * TCP Vegas congestion control interface
 */
#ifndef __TCP_VEGAS_H
#define __TCP_VEGAS_H 1

/* My TCPProbe Appendix */
struct probeAppendix {
	//Base Appendix Struct fields
	char 	last_decision;
	u32	bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
	u32	bw_est;           /* bandwidth estimate */

	//Overflow Struct fields from CUBIC
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
	u32	round_start;	/* beginning of each round */

	//Bandwidth Estimation fields
	u32    rtt_win_sx;       /* here starts a new evaluation... */
        u32    bk;
        u32    snd_una;          /* used for evaluating the number of acked bytes */
        u32    cumul_ack;
        u32    accounted;
        u32    rtt;
        u8     first_ack;        /* flag which infers that this is the first ack */
};

struct vegas {
	char	flag;
	struct probeAppendix *appendix;

	/* Vegas variables */
	u32	beg_snd_nxt;	/* right edge during last RTT */
	u32	beg_snd_una;	/* left edge  during last RTT */
	u32	beg_snd_cwnd;	/* saves the size of the cwnd */
	u8	doing_vegas_now;/* if true, do vegas for this RTT */
	u16	cntRTT;		/* # of RTTs measured within last RTT */
	u32	minRTT;		/* min of RTTs measured within last RTT (in usec) */
	u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) */
};

void tcp_vegas_init(struct sock *sk);
void tcp_vegas_state(struct sock *sk, u8 ca_state);
void tcp_vegas_pkts_acked(struct sock *sk, u32 cnt, s32 rtt_us);
void tcp_vegas_cwnd_event(struct sock *sk, enum tcp_ca_event event);
void tcp_vegas_get_info(struct sock *sk, u32 ext, struct sk_buff *skb);

#endif	/* __TCP_VEGAS_H */
