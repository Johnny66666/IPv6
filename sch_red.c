/*
 * net/sched/sch_red.c	Random Early Detection queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 * J Hadi Salim 980914:	computation fixes
 * Alexey Makarenko <makar@phoenix.kharkov.ua> 990814: qave on idle link was calculated incorrectly.
 * J Hadi Salim 980816:  ECN support
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>
#include <net/red.h>
/*
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#define MY_FILE "/home/server/myfile.tr"
*/

//#include <stdio.h>
//#include <stdlib.h>
int fin_counter = 0;

__u32 first_time = 0;
int jnmark = 0;
//__u8 jn_fetch = 0;
int jncount[10] = {0};


int flow_counter = 0;

//int packet_counter = 0;
int flag = 0;
int jnflag[10] = {0}; 

int wholethroughput = 100;  
s64 first_packet=0; 
s64 now_time=0;
s64 timegap = 20600; 
int databyte = 0;

s64 now_time2 = 0;

int i = 0; 
int j = 0;
int num[100]={0};
int array[10] = {0};
int sportrec = 0;
int dportrec = 0;
int now_throughput[10] = {0};  
int improve_th[10] = {0};
int goal = 0;

u_int32_t jnseq = 1;



/*	Parameters, settable by user:
	-----------------------------

	limit		- bytes (must be > qth_max + burst)

	Hard limit on queue length, should be chosen >qth_max
	to allow packet bursts. This parameter does not
	affect the algorithms behaviour and can be chosen
	arbitrarily high (well, less than ram size)
	Really, this limit will never be reached
	if RED works correctly.
 */

struct red_sched_data {
	u32			limit;		/* HARD maximal queue length */
	unsigned char		flags;
	struct timer_list	adapt_timer;
	struct red_parms	parms;
	struct red_vars		vars;
	struct red_stats	stats;
	struct Qdisc		*qdisc;
};

static inline int red_use_ecn(struct red_sched_data *q)
{
	return q->flags & TC_RED_ECN;
}

static inline int red_use_harddrop(struct red_sched_data *q)
{
	return q->flags & TC_RED_HARDDROP;
}
/*
void writeFormatted(FILE * stream, const char * format, ...){
va_list args;
va_start(args, format);
vfprintf(stream,format,args);
va_end(args);
}
*/
static int red_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	int ret;
	
	struct tcphdr *th;
	struct ipv6hdr *hdr;
	hdr = ipv6_hdr(skb);
	th = tcp_hdr(skb);

	sportrec = htons(th->source);
	dportrec = htons(th->dest);

	
	if(th->syn && th->ack == 1)
	{
		for(j=0;j<10;j++)
			{
			if(sportrec == array[j])
				break; 	
			else{
				array[i] =  dportrec;
				i++;
				flow_counter++;
				break;
				}			
			}  
	}

	if(th->fin && th->ack == 1)
	{
		for(j=0;j<10;j++)
			{
			if(sportrec == array[j])
				array[j]=0; 
				fin_counter += 1 ;
			}
 		
	}
	
	if(fin_counter == 2)
		{
		--flow_counter;
		fin_counter = 0;
		}

	 now_time = ktime_to_us(ktime_get());
	 
	 if(skb->len > 500)
	{
		if (flag == 0)
                {
               first_packet = now_time; 
               flag=1;
                }
		for(j=0;j<10;j++)
		{
			if(sportrec == array[j])
				num[j] = num[j] + 1;
		}
	}	
		
	if((now_time - first_packet) > timegap && flow_counter != 0)
  	{
  		for(j=0;j<10;j++)
  		{
  			now_throughput[j] = num[j]*1460/timegap*8;  
			goal = wholethroughput/flow_counter;   
			improve_th[j] = goal - now_throughput[j];
			
			if(improve_th[j] > 7)
				{
					jncount[j] = 7;
				}
			else if (improve_th[j] <= 7 && improve_th[j] >=0)
				{
					jncount[j] = improve_th[j];
				}
			else if (improve_th[j] < 0 && improve_th[j] >= -8)
				{
					jncount[j] = 7 - improve_th[j] ;
				}
			else 
				{
					jncount[j] = 15 ;
				}
			improve_th[j]=0;
			now_throughput[j]=0;
			first_packet = now_time;
			num[j] = 0;
			jnflag[j] = 1;
   		} 
  	
	}
			
	if(th->ack)
	{
		jnseq = ntohl(th->ack_seq);	
		for(j=0;j<10;j++)
		{
			if(dportrec == array[j] && jnflag[j] ==1)
			{
				
				hdr->priority = jncount[j]; 
				jnflag[j] = 0 ;
			}		
		}
	}
	
	
	q->vars.qavg = red_calc_qavg(&q->parms,
				     &q->vars,
				     child->qstats.backlog);

	if (red_is_idling(&q->vars))
		red_end_of_idle_period(&q->vars);

	if(sch->q.qlen>64){
	q->stats.forced_drop++;
	goto congestion_drop;
				}

	ret = qdisc_enqueue(skb, child);
	if (likely(ret == NET_XMIT_SUCCESS)) {
		sch->q.qlen++;
	} else if (net_xmit_drop_count(ret)) {
		q->stats.pdrop++;
		qdisc_qstats_drop(sch);
	}
	return ret;

congestion_drop:
	qdisc_drop(skb, sch);	
	return NET_XMIT_CN;
}

static struct sk_buff *red_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb;
	struct red_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	
	struct tcphdr *th;
	
	u32 dport;
	u32 sport;
	u32 seq;

	skb = child->dequeue(child);

	
	
	
	now_time2 = ktime_to_us(ktime_get());


	if (skb) {
		th = tcp_hdr(skb);
		dport = htons(th->dest);
		sport = htons(th->source);
		seq = ntohl(th->seq);
					
		qdisc_bstats_update(sch, skb);
		sch->q.qlen--;
	} else {
		if (!red_is_idling(&q->vars))
			red_start_of_idle_period(&q->vars);
	}
	return skb;
}

static struct sk_buff *red_peek(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;

	return child->ops->peek(child);
}

static unsigned int red_drop(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct Qdisc *child = q->qdisc;
	unsigned int len;

	if (child->ops->drop && (len = child->ops->drop(child)) > 0) {
		q->stats.other++;
		qdisc_qstats_drop(sch);
		sch->q.qlen--;
		return len;
	}

	if (!red_is_idling(&q->vars))
		red_start_of_idle_period(&q->vars);

	return 0;
}

static void red_reset(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	sch->q.qlen = 0;
	red_restart(&q->vars);
}

static void red_destroy(struct Qdisc *sch)
{
	struct red_sched_data *q = qdisc_priv(sch);

	del_timer_sync(&q->adapt_timer);
	qdisc_destroy(q->qdisc);
}

static const struct nla_policy red_policy[TCA_RED_MAX + 1] = {
	[TCA_RED_PARMS]	= { .len = sizeof(struct tc_red_qopt) },
	[TCA_RED_STAB]	= { .len = RED_STAB_SIZE },
	[TCA_RED_MAX_P] = { .type = NLA_U32 },
};

static int red_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_RED_MAX + 1];
	struct tc_red_qopt *ctl;
	struct Qdisc *child = NULL;
	int err;
	u32 max_P;

	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_RED_MAX, opt, red_policy);
	if (err < 0)
		return err;

	if (tb[TCA_RED_PARMS] == NULL ||
	    tb[TCA_RED_STAB] == NULL)
		return -EINVAL;

	max_P = tb[TCA_RED_MAX_P] ? nla_get_u32(tb[TCA_RED_MAX_P]) : 0;

	ctl = nla_data(tb[TCA_RED_PARMS]);

	if (ctl->limit > 0) {
		child = fifo_create_dflt(sch, &bfifo_qdisc_ops, ctl->limit);
		if (IS_ERR(child))
			return PTR_ERR(child);
	}

	sch_tree_lock(sch);
	q->flags = ctl->flags;
	q->limit = ctl->limit;
	if (child) {
		qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
		qdisc_destroy(q->qdisc);
		q->qdisc = child;
	}

	red_set_parms(&q->parms,
		      ctl->qth_min, ctl->qth_max, ctl->Wlog,
		      ctl->Plog, ctl->Scell_log,
		      nla_data(tb[TCA_RED_STAB]),
		      max_P);
	red_set_vars(&q->vars);

	del_timer(&q->adapt_timer);
	if (ctl->flags & TC_RED_ADAPTATIVE)
		mod_timer(&q->adapt_timer, jiffies + HZ/2);

	if (!q->qdisc->q.qlen)
		red_start_of_idle_period(&q->vars);

	sch_tree_unlock(sch);
	return 0;
}

static inline void red_adaptative_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct red_sched_data *q = qdisc_priv(sch);
	spinlock_t *root_lock = qdisc_lock(qdisc_root_sleeping(sch));

	spin_lock(root_lock);
	red_adaptative_algo(&q->parms, &q->vars);
	mod_timer(&q->adapt_timer, jiffies + HZ/2);
	spin_unlock(root_lock);
}

static int red_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct red_sched_data *q = qdisc_priv(sch);

	q->qdisc = &noop_qdisc;
	setup_timer(&q->adapt_timer, red_adaptative_timer, (unsigned long)sch);
	return red_change(sch, opt);
}

static int red_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = NULL;
	struct tc_red_qopt opt = {
		.limit		= q->limit,
		.flags		= q->flags,
		.qth_min	= q->parms.qth_min >> q->parms.Wlog,
		.qth_max	= q->parms.qth_max >> q->parms.Wlog,
		.Wlog		= q->parms.Wlog,
		.Plog		= q->parms.Plog,
		.Scell_log	= q->parms.Scell_log,
	};

	sch->qstats.backlog = q->qdisc->qstats.backlog;
	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	if (nla_put(skb, TCA_RED_PARMS, sizeof(opt), &opt) ||
	    nla_put_u32(skb, TCA_RED_MAX_P, q->parms.max_P))
		goto nla_put_failure;
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -EMSGSIZE;
}

static int red_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct red_sched_data *q = qdisc_priv(sch);
	struct tc_red_xstats st = {
		.early	= q->stats.prob_drop + q->stats.forced_drop,
		.pdrop	= q->stats.pdrop,
		.other	= q->stats.other,
		.marked	= q->stats.prob_mark + q->stats.forced_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int red_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct red_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;
	return 0;
}

static int red_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct red_sched_data *q = qdisc_priv(sch);

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->qdisc;
	q->qdisc = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);
	return 0;
}

static struct Qdisc *red_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct red_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}

static unsigned long red_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void red_put(struct Qdisc *sch, unsigned long arg)
{
}

static void red_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops red_class_ops = {
	.graft		=	red_graft,
	.leaf		=	red_leaf,
	.get		=	red_get,
	.put		=	red_put,
	.walk		=	red_walk,
	.dump		=	red_dump_class,
};

static struct Qdisc_ops red_qdisc_ops __read_mostly = {
	.id		=	"red",
	.priv_size	=	sizeof(struct red_sched_data),
	.cl_ops		=	&red_class_ops,
	.enqueue	=	red_enqueue,
	.dequeue	=	red_dequeue,
	.peek		=	red_peek,
	.drop		=	red_drop,
	.init		=	red_init,
	.reset		=	red_reset,
	.destroy	=	red_destroy,
	.change		=	red_change,
	.dump		=	red_dump,
	.dump_stats	=	red_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init red_module_init(void)
{
	return register_qdisc(&red_qdisc_ops);
}

static void __exit red_module_exit(void)
{
	unregister_qdisc(&red_qdisc_ops);
	
}

module_init(red_module_init)
module_exit(red_module_exit)

MODULE_LICENSE("GPL");
