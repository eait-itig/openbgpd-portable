/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright 2022 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/mac.h>
#include <inet/mib2.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inet/ip.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>

#include "bgpd.h"
#include "log.h"

struct ktable		**krt;
u_int			  krt_size;

struct {
	u_int32_t		rtseq;
	pid_t			pid;
	int			fd;
	u_int8_t		fib_prio;
} kr_state;

struct kroute {
	RB_ENTRY(kroute)	 entry;
	struct kroute		*next;
	struct in_addr		 prefix;
	struct in_addr		 nexthop;
	uint32_t		 mplslabel;
	uint16_t		 flags;
	uint16_t		 labelid;
	u_short			 ifindex;
	uint8_t			 prefixlen;
	uint8_t			 priority;
	struct kif		*kif;
};

struct kroute6 {
	RB_ENTRY(kroute6)	 entry;
	struct kroute6		*next;
	struct in6_addr		 prefix;
	struct in6_addr		 nexthop;
	uint32_t		 prefix_scope_id;	/* because ... */
	uint32_t		 nexthop_scope_id;
	uint32_t		 mplslabel;
	uint16_t		 flags;
	uint16_t		 labelid;
	u_short			 ifindex;
	uint8_t			 prefixlen;
	uint8_t			 priority;
	struct kif		*kif;
};

struct knexthop {
	RB_ENTRY(knexthop)	 entry;
	struct bgpd_addr	 nexthop;
	void			*kroute;
	u_short			 ifindex;
};

struct kredist_node {
	RB_ENTRY(kredist_node)	 entry;
	struct bgpd_addr	 prefix;
	u_int64_t		 rd;
	u_int8_t		 prefixlen;
	u_int8_t		 dynamic;
};

struct kif_kr {
	LIST_ENTRY(kif_kr)	 entry;
	struct kroute	*kr;
};

struct kif_kr6 {
	LIST_ENTRY(kif_kr6)	 entry;
	struct kroute6	*kr;
};

LIST_HEAD(kif_kr_head, kif_kr);
LIST_HEAD(kif_kr6_head, kif_kr6);

struct kif {
	RB_ENTRY(kif)		 entry;
	char			 ifname[IFNAMSIZ];
	uint64_t		 baudrate;
	u_int			 rdomain;
	int			 flags;
	u_short			 ifindex;
	uint8_t			 if_type;
	uint8_t			 link_state;
	uint8_t			 nh_reachable;	/* for nexthop verification */
	uint8_t			 depend_state;	/* for session depend on */
	struct kif_kr_head	 kroute_l;
	struct kif_kr6_head	 kroute6_l;
};

int	ktable_new(u_int, u_int, char *, int);
void	ktable_free(u_int);
void	ktable_destroy(struct ktable *);
struct ktable	*ktable_get(u_int);

int	kr4_change(struct ktable *, struct kroute_full *);
int	kr6_change(struct ktable *, struct kroute_full *);
int	krVPN4_change(struct ktable *, struct kroute_full *);
int	krVPN6_change(struct ktable *, struct kroute_full *);
int	kr4_delete(struct ktable *, struct kroute_full *);
int	kr6_delete(struct ktable *, struct kroute_full *);
int	krVPN4_delete(struct ktable *, struct kroute_full *);
int	krVPN6_delete(struct ktable *, struct kroute_full *);
void	kr_net_delete(struct network *);
int	kr_net_match(struct ktable *, struct network_config *, u_int16_t, int);
struct network *kr_net_find(struct ktable *, struct network *);
void	kr_net_clear(struct ktable *);
void	kr_redistribute(int, struct ktable *, struct kroute *);
void	kr_redistribute6(int, struct ktable *, struct kroute6 *);
uint8_t	kr_priority(struct kroute_full *);
struct kroute_full *kr_tofull(struct kroute *);
struct kroute_full *kr6_tofull(struct kroute6 *);
int	kroute_compare(struct kroute *, struct kroute *);
int	kroute6_compare(struct kroute6 *, struct kroute6 *);
int	knexthop_compare(struct knexthop *, struct knexthop *);
int	kredist_compare(struct kredist_node *, struct kredist_node *);
int	kif_compare(struct kif *, struct kif *);
void	kr_fib_update_prio(u_int, u_int8_t);
int	kroute_post_insert(struct ktable *, struct kroute *,
	    struct kroute *);

static char *octetstr(const Octet_t *, int, char *, uint_t);

struct kroute	*kroute_find(struct ktable *, struct in_addr,
		    uint8_t, uint8_t);
struct kroute	*kroute_matchgw(struct kroute *, struct sockaddr_in *);
int		 kroute_insert(struct ktable *, struct kroute *);
int		 kroute_remove(struct ktable *, struct kroute *);
void		 kroute_clear(struct ktable *);

struct kroute6	*kroute6_find(struct ktable *, const struct in6_addr *,
		    uint8_t, uint8_t);
struct kroute6	*kroute6_matchgw(struct kroute6 *, struct sockaddr_in6 *);
int		 kroute6_insert(struct ktable *, struct kroute6 *);
int		 kroute6_remove(struct ktable *, struct kroute6 *);
void		 kroute6_clear(struct ktable *);

struct knexthop	*knexthop_find(struct ktable *, struct bgpd_addr *);
int		 knexthop_insert(struct ktable *, struct knexthop *);
int		 knexthop_remove(struct ktable *, struct knexthop *);
void		 knexthop_clear(struct ktable *);

struct kif		*kif_find(int);
int			 kif_insert(struct kif *);
int			 kif_remove(struct kif *);
void			 kif_clear(void);

int			 kif_kr_insert(struct kroute *);
int			 kif_kr_remove(struct kroute *);

int			 kif_kr6_insert(struct kroute6 *);
int			 kif_kr6_remove(struct kroute6 *);

int		 kroute_validate(struct kroute *);
int		 kroute6_validate(struct kroute6 *);
int		 knexthop_true_nexthop(struct ktable *, struct kroute_full *);
void		 knexthop_validate(struct ktable *, struct knexthop *);
void		 knexthop_track(struct ktable *, u_short);
void		 knexthop_update(struct ktable *, struct kroute_full *);
void		 knexthop_send_update(struct knexthop *);
struct kroute	*kroute_match(struct ktable *, struct bgpd_addr *, int);
struct kroute6	*kroute6_match(struct ktable *, struct bgpd_addr *, int);
void		 kroute_detach_nexthop(struct ktable *, struct knexthop *);

int		protect_lo(struct ktable *);
u_int8_t	prefixlen_classful(in_addr_t);
u_int8_t	mask2prefixlen(in_addr_t);
u_int8_t	mask2prefixlen6(struct sockaddr_in6 *);
uint64_t	ift2ifm(uint8_t);
const char	*get_media_descr(uint64_t);
const char	*get_linkstate(uint8_t, int);
void		get_rtaddrs(int, struct sockaddr *, struct sockaddr **);

int		send_rtmsg(int, int, struct ktable *, struct kroute *);
int		send_rt6msg(int, int, struct ktable *, struct kroute6 *);
int		dispatch_rtmsg(void);
int		fetchtable(struct ktable *, int);
int		fetchifs(int);
int		dispatch_rtmsg_addr(struct rt_msghdr *,
		    struct sockaddr *[RTAX_MAX], struct ktable *);
int		dispatch_rtmsg_if(const struct if_msghdr *, struct ktable *);

RB_PROTOTYPE(kroute_tree, kroute, entry, kroute_compare)
RB_GENERATE(kroute_tree, kroute, entry, kroute_compare)

RB_PROTOTYPE(kroute6_tree, kroute6, entry, kroute6_compare)
RB_GENERATE(kroute6_tree, kroute6, entry, kroute6_compare)

RB_PROTOTYPE(knexthop_tree, knexthop, entry, knexthop_compare)
RB_GENERATE(knexthop_tree, knexthop, entry, knexthop_compare)

RB_PROTOTYPE(kredist_tree, kredist_node, entry, kredist_compare)
RB_GENERATE(kredist_tree, kredist_node, entry, kredist_compare)

RB_HEAD(kif_tree, kif)		kit;
RB_PROTOTYPE(kif_tree, kif, entry, kif_compare)
RB_GENERATE(kif_tree, kif, entry, kif_compare)

#define KT2KNT(x)	(&(ktable_get((x)->nhtableid)->knt))

/*
 * exported functions
 */

int
get_mpe_config(const char *name, u_int *rdomain, u_int *label)
{
	return (-1);
}

int
kr_init(int *fd, uint8_t fib_prio)
{
	int		opt = 0, rcvbuf, default_rcvbuf;
	socklen_t	optlen;

	if ((kr_state.fd = socket(AF_ROUTE,
	    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	/* not interested in my own messages */
	if (setsockopt(kr_state.fd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		log_warn("%s: setsockopt", __func__);	/* not fatal */

	/* grow receive buffer, don't wanna miss messages */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kr_state.fd, SOL_SOCKET, SO_RCVBUF,
	    &default_rcvbuf, &optlen) == -1)
		log_warn("%s: getsockopt SOL_SOCKET SO_RCVBUF", __func__);
	else
		for (rcvbuf = MAX_RTSOCK_BUF;
		    rcvbuf > default_rcvbuf &&
		    setsockopt(kr_state.fd, SOL_SOCKET, SO_RCVBUF,
		    &rcvbuf, sizeof(rcvbuf)) == -1 && errno == ENOBUFS;
		    rcvbuf /= 2)
			;	/* nothing */

	kr_state.pid = getpid();
	kr_state.rtseq = 1;
	kr_state.fib_prio = fib_prio;

	RB_INIT(&kit);

	if (fetchifs(0) == -1)
		return (-1);

	*fd = kr_state.fd;
	return (0);
}

int
kr_default_prio(void)
{
	return (RTP_BGP);
}

int
kr_check_prio(long long prio)
{
	if (prio <= RTP_LOCAL || prio > RTP_MAX)
		return (0);
	return (1);
}

int
ktable_new(u_int rtableid, u_int rdomid, char *name, int fs)
{
	struct ktable	**xkrt;
	struct ktable	 *kt;
	size_t		  oldsize;

	/* resize index table if needed */
	if (rtableid >= krt_size) {
		oldsize = sizeof(struct ktable *) * krt_size;
		if ((xkrt = reallocarray(krt, rtableid + 1,
		    sizeof(struct ktable *))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		krt = xkrt;
		krt_size = rtableid + 1;
		bzero((char *)krt + oldsize,
		    krt_size * sizeof(struct ktable *) - oldsize);
	}

	if (krt[rtableid])
		fatalx("ktable_new: table already exists.");

	/* allocate new element */
	kt = krt[rtableid] = calloc(1, sizeof(struct ktable));
	if (kt == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}

	/* initialize structure ... */
	strlcpy(kt->descr, name, sizeof(kt->descr));
	RB_INIT(&kt->krt);
	RB_INIT(&kt->krt6);
	RB_INIT(&kt->knt);
	TAILQ_INIT(&kt->krn);
	kt->fib_conf = kt->fib_sync = fs;
	kt->rtableid = rtableid;
	kt->nhtableid = rdomid;
	/* bump refcount of rdomain table for the nexthop lookups */
	ktable_get(kt->nhtableid)->nhrefcnt++;

	if (fetchtable(kt, 1) == -1)
		return (-1);

	/* everything is up and running */
	kt->state = RECONF_REINIT;
	log_debug("%s: %s with rtableid %d rdomain %d", __func__, name,
	    rtableid, rdomid);
	return (0);
}

void
ktable_free(u_int rtableid)
{
	struct ktable	*kt, *nkt;

	if ((kt = ktable_get(rtableid)) == NULL)
		return;

	/* decouple from kernel, no new routes will be entered from here */
	kr_fib_decouple(kt->rtableid);

	/* first unhook from the nexthop table */
	nkt = ktable_get(kt->nhtableid);
	nkt->nhrefcnt--;

	/*
	 * Evil little details:
	 *   If kt->nhrefcnt > 0 then kt == nkt and nothing needs to be done.
	 *   If kt != nkt then kt->nhrefcnt must be 0 and kt must be killed.
	 *   If nkt is no longer referenced it must be killed (possible double
	 *   free so check that kt != nkt).
	 */
	if (kt != nkt && nkt->nhrefcnt <= 0)
		ktable_destroy(nkt);
	if (kt->nhrefcnt <= 0)
		ktable_destroy(kt);
}

void
ktable_destroy(struct ktable *kt)
{
	/* decouple just to be sure, does not hurt */
	kr_fib_decouple(kt->rtableid);

	log_debug("%s: freeing ktable %s rtableid %u", __func__, kt->descr,
	    kt->rtableid);
	/* only clear nexthop table if it is the main rdomain table */
	if (kt->rtableid == kt->nhtableid)
		knexthop_clear(kt);
	kroute_clear(kt);
	kroute6_clear(kt);
	kr_net_clear(kt);

	krt[kt->rtableid] = NULL;
	free(kt);
}

struct ktable *
ktable_get(u_int rtableid)
{
	if (rtableid >= krt_size)
		return (NULL);
	return (krt[rtableid]);
}

int
ktable_update(u_int rtableid, char *name, int flags)
{
	struct ktable	*kt, *rkt;
	u_int		 rdomid;

	if (!ktable_exists(rtableid, &rdomid))
		fatalx("King Bula lost a table");	/* may not happen */

	if (rdomid != rtableid || flags & F_RIB_NOFIB) {
		rkt = ktable_get(rdomid);
		if (rkt == NULL) {
			char buf[32];
			snprintf(buf, sizeof(buf), "rdomain_%d", rdomid);
			if (ktable_new(rdomid, rdomid, buf, 0))
				return (-1);
		} else {
			/* there is no need for full fib synchronisation if
			 * the table is only used for nexthop lookups.
			 */
			if (rkt->state == RECONF_DELETE) {
				rkt->fib_conf = 0;
				rkt->state = RECONF_KEEP;
			}
		}
	}

	if (flags & (F_RIB_NOFIB | F_RIB_NOEVALUATE))
		/* only rdomain table must exist */
		return (0);

	kt = ktable_get(rtableid);
	if (kt == NULL) {
		if (ktable_new(rtableid, rdomid, name,
		    !(flags & F_RIB_NOFIBSYNC)))
			return (-1);
	} else {
		/* fib sync has higher preference then no sync */
		if (kt->state == RECONF_DELETE) {
			kt->fib_conf = !(flags & F_RIB_NOFIBSYNC);
			kt->state = RECONF_KEEP;
		} else if (!kt->fib_conf)
			kt->fib_conf = !(flags & F_RIB_NOFIBSYNC);

		strlcpy(kt->descr, name, sizeof(kt->descr));
	}
	return (0);
}

int
ktable_exists(u_int rtableid, u_int *rdomid)
{
	if (rtableid == 0) {
		*rdomid = 0;
		return (1);
	}
	return (0);
}

int
kr_change(u_int rtableid, struct kroute_full *kl)
{
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);
	switch (kl->prefix.aid) {
	case AID_INET:
		return (kr4_change(kt, kl));
	case AID_INET6:
		return (kr6_change(kt, kl));
	}
	log_warnx("%s: not handled AID", __func__);
	return (-1);
}

int
kr4_change(struct ktable *kt, struct kroute_full *kl)
{
	struct kroute	*kr, *okr;

	/* for blackhole and reject routes nexthop needs to be 127.0.0.1 */
	if (kl->flags & (F_BLACKHOLE|F_REJECT))
		kl->nexthop.v4.s_addr = htonl(INADDR_LOOPBACK);
	/* nexthop within 127/8 -> ignore silently */
	else if ((kl->nexthop.v4.s_addr & htonl(IN_CLASSA_NET)) ==
	    htonl(INADDR_LOOPBACK & IN_CLASSA_NET))
		return (0);

	/*
	 * RTM_CHANGE doesn't let you change gateways on illumos. It only lets
	 * you change some subset of flags and metrics.
	 *
	 * We're not going to bother ever using it here, we'll just delete the
	 * route and add a new one. Yes, that means a window where there's no
	 * route. illumos was never going to be a very good router anyway.
	 */
	okr = kroute_find(kt, kl->prefix.v4, kl->prefixlen, kr_state.fib_prio);
	if (okr != NULL) {
		if (!(okr->flags & F_BGPD_INSERTED)) {
			log_warnx("%s: existing route to %s/%u with our prio "
			    "but we didn't insert it (?)", __func__,
			    inet_ntoa(okr->prefix), okr->prefixlen);
			return (-1);
		}
		if (send_rtmsg(kr_state.fd, RTM_DELETE, kt, okr) == -1)
			return (-1);
		if (kroute_remove(kt, okr) == -1)
			return (-1);
	}

	if ((kr = calloc(1, sizeof(struct kroute))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	kr->prefix = kl->prefix.v4;
	kr->prefixlen = kl->prefixlen;
	kr->nexthop = kl->nexthop.v4;
	kr->flags = kl->flags | F_BGPD_INSERTED;
	kr->priority = kr_state.fib_prio;
	rtlabel_unref(kr->labelid);
	kr->labelid = rtlabel_name2id(kl->label);

	if (kroute_insert(kt, kr) == -1) {
		free(kr);
		return (-1);
	}

	if (send_rtmsg(kr_state.fd, RTM_ADD, kt, kr) == -1)
		return (-1);

	return (0);
}

typedef struct mib_item_s {
	struct mib_item_s *next_item;
	long group;
	long mib_id;
	long length;
	intmax_t *valp;
} mib_item_t;

static void
mibfree(mib_item_t *item)
{
	mib_item_t *prev;

	while (item != NULL) {
		prev = item;
		item = item->next_item;
		free(prev->valp);
		free(prev);
	}
}

static mib_item_t *
mibget(int sd)
{
	intmax_t		buf[512 / sizeof (intmax_t)];
	int			flags;
	int			j, getcode;
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;
	mib_item_t		*first_item = NULL;
	mib_item_t		*last_item  = NULL;
	mib_item_t		*temp;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;
	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, NULL, flags) < 0) {
		perror("mibget: putmsg (ctl)");
		return (NULL);
	}
	/*
	 * each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	for (j = 1; ; j++) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, NULL, &flags);
		if (getcode < 0) {
			perror("mibget: getmsg (ctl)");
			break;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= (int)(sizeof (struct T_optmgmt_ack)) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0) {
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= (int)(sizeof (struct T_error_ack)) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			(void) fprintf(stderr, "mibget %d gives "
			    "T_ERROR_ACK: TLI_error = 0x%x, UNIX_error = "
			    "0x%x\n", j, tea->TLI_error, tea->UNIX_error);
			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			break;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < (int)(sizeof (struct T_optmgmt_ack)) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			(void) printf("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %d\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);
			if (toa->PRIM_type == T_OPTMGMT_ACK) {
				(void) printf("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%x, req->len = %d\n",
				    toa->MGMT_flags, req->len);
			}
			errno = ENOMSG;
			break;
		}

		temp = malloc(sizeof (mib_item_t));
		if (temp == NULL) {
			perror("mibget: malloc");
			break;
		}
		if (last_item != NULL)
			last_item->next_item = temp;
		else
			first_item = temp;
		last_item = temp;
		last_item->next_item = NULL;
		last_item->group = req->level;
		last_item->mib_id = req->name;
		last_item->length = req->len;
		last_item->valp = malloc(req->len);

		databuf.maxlen = last_item->length;
		databuf.buf    = (char *)last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, NULL, &databuf, &flags);
		if (getcode < 0) {
			perror("mibget: getmsg (data)");
			break;
		} else if (getcode != 0) {
			(void) printf("mibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			break;
		}
	}

	/*
	 * On error, free all the allocated mib_item_t objects.
	 */
	mibfree(first_item);
	return (NULL);
}

int
fetchtable(struct ktable *kt, int init)
{
	int 			sd;
	mib2_ipRouteEntry_t	*rp;
	size_t			rentsz = 0;
	mib_item_t		*item0 = NULL, *item;
	struct kroute	*kr = NULL, *kru;
	int			ire_type, ire_flags;
	int 			rc;
	int			insert;
	char			ifname[LIFNAMSIZ + 1];

	log_warnx("%s: refreshing full table from mib2", __func__);

	sd = open("/dev/ip", O_RDWR);
	if (sd == -1) {
		log_warn("%s: open(/dev/ip)", __func__);
		return (-1);
	}

	item0 = mibget(sd);
	if (item0 == NULL) {
		rc = -1;
		goto done;
	}

	for (item = item0; item != NULL; item = item->next_item) {
		if (item->mib_id != 0)
			continue;
		if (item->group == MIB2_IP) {
			rentsz = ((mib2_ip_t *)item->valp)->ipRouteEntrySize;
			break;
		}
	}
	if (rentsz == 0) {
		rc = -1;
		goto done;
	}
	for (item = item0; item != NULL; item = item->next_item) {
		if (item->group != MIB2_IP ||
		    item->mib_id != MIB2_IP_ROUTE)
			continue;
		for (rp = (mib2_ipRouteEntry_t *)item->valp;
		    (char *)rp < (char *)item->valp + item->length;
		    rp = (mib2_ipRouteEntry_t *)((char *)rp + rentsz)) {
			ire_type = rp->ipRouteInfo.re_ire_type;
			ire_flags = rp->ipRouteInfo.re_flags;

			if (ire_type != IRE_DEFAULT &&
			    ire_type != IRE_PREFIX &&
			    ire_type != IRE_HOST &&
			    ire_type != IRE_LOCAL &&
			    (ire_type & IRE_INTERFACE) == 0)
				continue;

			if ((kr = calloc(1, sizeof(struct kroute))) ==
			    NULL) {
				log_warn("%s", __func__);
				rc = -1;
				goto done;
			}
			insert = 1;

			kr->priority = 0;
			if (ire_flags & RTF_PROTO2)
				kr->priority = kr_state.fib_prio;
			kr->prefix.s_addr = rp->ipRouteDest;
			if (ire_flags & RTF_HOST)
				kr->prefixlen = 32;
			else
				kr->prefixlen = mask2prefixlen(rp->ipRouteMask);

			kru = kroute_find(kt, kr->prefix, kr->prefixlen,
			    kr->priority);
			if (kru != NULL) {
				free(kr);
				kr = kru;
				insert = 0;
			}

			if (ire_flags & RTF_STATIC)
				kr->flags |= F_STATIC;
			if (ire_flags & RTF_BLACKHOLE)
				kr->flags |= F_BLACKHOLE;
			if (ire_flags & RTF_REJECT)
				kr->flags |= F_REJECT;
			if (ire_type == IRE_LOCAL || (ire_type & IRE_INTERFACE))
				kr->flags |= F_CONNECTED;
			kr->nexthop.s_addr = rp->ipRouteNextHop;

			octetstr(&rp->ipRouteIfIndex, 'a',
			    ifname, sizeof (ifname));
			if (strlen(ifname) > 0)
				kr->ifindex = if_nametoindex(ifname);

			if (insert && (ire_flags & RTF_PROTO2)) {
				log_warnx("deleting pre-existing route to %s/%u",
				    inet_ntoa(kr->prefix), kr->prefixlen);
				send_rtmsg(kr_state.fd, RTM_DELETE, kt, kr);
				free(kr);
				continue;
			}

			if (insert)
				kroute_insert(kt, kr);
			else
				kroute_post_insert(kt, kr, NULL);
		}
		break;
	}

	rc = 0;

done:
	close(sd);
	mibfree(item0);
	return (rc);
}

int
kr6_change(struct ktable *kt, struct kroute_full *kl)
{
	struct kroute6	*kr6;
	struct in6_addr		 lo6 = IN6ADDR_LOOPBACK_INIT;
	int			 action = RTM_ADD;
	u_int16_t		 labelid;

	/* for blackhole and reject routes nexthop needs to be ::1 */
	if (kl->flags & (F_BLACKHOLE|F_REJECT))
		bcopy(&lo6, &kl->nexthop.v6, sizeof(kl->nexthop.v6));
	/* nexthop to loopback -> ignore silently */
	else if (IN6_IS_ADDR_LOOPBACK(&kl->nexthop.v6))
		return (0);

	labelid = rtlabel_name2id(kl->label);

	if ((kr6 = kroute6_find(kt, &kl->prefix.v6, kl->prefixlen,
	    kr_state.fib_prio)) != NULL) {
		action = RTM_CHANGE;
	}

	if (action == RTM_ADD) {
		if ((kr6 = calloc(1, sizeof(struct kroute6))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		memcpy(&kr6->prefix, &kl->prefix.v6, sizeof(struct in6_addr));
		kr6->prefixlen = kl->prefixlen;
		memcpy(&kr6->nexthop, &kl->nexthop.v6,
		    sizeof(struct in6_addr));
		kr6->flags = kl->flags | F_BGPD_INSERTED;
		kr6->priority = kr_state.fib_prio;
		kr6->labelid = labelid;

		if (kroute6_insert(kt, kr6) == -1) {
			free(kr6);
			return (-1);
		}
	} else {
		memcpy(&kr6->nexthop, &kl->nexthop.v6,
		    sizeof(struct in6_addr));
		rtlabel_unref(kr6->labelid);
		kr6->labelid = labelid;
		if (kl->flags & F_BLACKHOLE)
			kr6->flags |= F_BLACKHOLE;
		else
			kr6->flags &= ~F_BLACKHOLE;
		if (kl->flags & F_REJECT)
			kr6->flags |= F_REJECT;
		else
			kr6->flags &= ~F_REJECT;
	}

	if (send_rt6msg(kr_state.fd, action, kt, kr6) == -1)
		return (-1);

	return (0);
}

int
kr_delete(u_int rtableid, struct kroute_full *kl)
{
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);

	switch (kl->prefix.aid) {
	case AID_INET:
		return (kr4_delete(kt, kl));
	case AID_INET6:
		return (kr6_delete(kt, kl));
	}
	log_warnx("%s: not handled AID", __func__);
	return (-1);
}

int
kr_flush(u_int rtableid)
{
	struct ktable		*kt;
	struct kroute	*kr, *next;
	struct kroute6	*kr6, *next6;

	if ((kt = ktable_get(rtableid)) == NULL)
		/* too noisy during reloads, just ignore */
		return (0);

	RB_FOREACH_SAFE(kr, kroute_tree, &kt->krt, next)
		if ((kr->flags & F_BGPD_INSERTED)) {
			if (kt->fib_sync)	/* coupled */
				send_rtmsg(kr_state.fd, RTM_DELETE, kt, kr);

			if (kroute_remove(kt, kr) == -1)
				return (-1);
		}
	RB_FOREACH_SAFE(kr6, kroute6_tree, &kt->krt6, next6)
		if ((kr6->flags & F_BGPD_INSERTED)) {
			if (kt->fib_sync)	/* coupled */
				send_rt6msg(kr_state.fd, RTM_DELETE, kt, kr6);

			if (kroute6_remove(kt, kr6) == -1)
				return (-1);
		}

	kt->fib_sync = 0;
	return (0);
}

int
kr4_delete(struct ktable *kt, struct kroute_full *kl)
{
	struct kroute	*kr;

	if ((kr = kroute_find(kt, kl->prefix.v4, kl->prefixlen,
	    kr_state.fib_prio)) == NULL) {
		return (0);
	}

	if (!(kr->flags & F_BGPD_INSERTED))
		return (0);

	if (send_rtmsg(kr_state.fd, RTM_DELETE, kt, kr) == -1)
		return (-1);

	if (kroute_remove(kt, kr) == -1)
		return (-1);

	return (0);
}

int
kr6_delete(struct ktable *kt, struct kroute_full *kl)
{
	struct kroute6	*kr6;

	if ((kr6 = kroute6_find(kt, &kl->prefix.v6, kl->prefixlen,
	     kr_state.fib_prio)) == NULL) {
		return (0);
	}

	if (!(kr6->flags & F_BGPD_INSERTED))
		return (0);

	if (send_rt6msg(kr_state.fd, RTM_DELETE, kt, kr6) == -1)
		return (-1);

	if (kroute6_remove(kt, kr6) == -1)
		return (-1);

	return (0);
}

void
kr_shutdown(void)
{
	u_int	i;

	for (i = krt_size; i > 0; i--)
		ktable_free(i - 1);
	kif_clear();
	free(krt);
}

void
kr_fib_couple(u_int rtableid)
{
	struct ktable		*kt;
	struct kroute	*kr;
	struct kroute6	*kr6;

	if ((kt = ktable_get(rtableid)) == NULL)  /* table does not exist */
		return;

	if (kt->fib_sync)	/* already coupled */
		return;

	fetchtable(kt, 0);
	kt->fib_sync = 1;

	RB_FOREACH(kr, kroute_tree, &kt->krt)
		if ((kr->flags & F_BGPD_INSERTED))
			send_rtmsg(kr_state.fd, RTM_ADD, kt, kr);
	RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
		if ((kr6->flags & F_BGPD_INSERTED))
			send_rt6msg(kr_state.fd, RTM_ADD, kt, kr6);

	log_info("kernel routing table %u (%s) coupled", kt->rtableid,
	    kt->descr);
}

void
kr_fib_couple_all(void)
{
	u_int	 i;

	for (i = krt_size; i > 0; i--)
		kr_fib_couple(i - 1);
}

void
kr_fib_decouple(u_int rtableid)
{
	struct ktable		*kt;
	struct kroute	*kr;
	struct kroute6	*kr6;

	if ((kt = ktable_get(rtableid)) == NULL)  /* table does not exist */
		return;

	if (!kt->fib_sync)	/* already decoupled */
		return;

	RB_FOREACH(kr, kroute_tree, &kt->krt)
		if ((kr->flags & F_BGPD_INSERTED))
			send_rtmsg(kr_state.fd, RTM_DELETE, kt, kr);
	RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
		if ((kr6->flags & F_BGPD_INSERTED))
			send_rt6msg(kr_state.fd, RTM_DELETE, kt, kr6);

	kt->fib_sync = 0;

	log_info("kernel routing table %u (%s) decoupled", kt->rtableid,
	    kt->descr);
}

void
kr_fib_decouple_all(void)
{
	u_int	 i;

	for (i = krt_size; i > 0; i--)
		kr_fib_decouple(i - 1);
}

static void
kr_fib_prio_set_rdom(u_int rdomain, u_int8_t fib_prio)
{
	struct ktable		*kt;
	struct kroute	*kr;
	struct kroute6	*kr6;

	if ((kt = ktable_get(rdomain)) == NULL)  /* table does not exist */
		return;

	RB_FOREACH(kr, kroute_tree, &kt->krt)
		if ((kr->flags & F_BGPD_INSERTED))
			kr->priority = fib_prio;

	RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
		if ((kr6->flags & F_BGPD_INSERTED))
			kr6->priority = fib_prio;
}

void
kr_fib_prio_set(u_int8_t fib_prio)
{
	u_int	 i;

	kr_state.fib_prio = fib_prio;

	for (i = krt_size; i > 0; i--)
		kr_fib_prio_set_rdom(i - 1, fib_prio);
}

int
kr_dispatch_msg(void)
{
	return (dispatch_rtmsg());
}

int
kr_nexthop_add(u_int rtableid, struct bgpd_addr *addr)
{
	struct ktable		*kt;
	struct knexthop	*h;

	if ((kt = ktable_get(rtableid)) == NULL) {
		log_warnx("%s: non-existent rtableid %d", __func__, rtableid);
		return (0);
	}
	if ((h = knexthop_find(kt, addr)) != NULL) {
		/* should not happen... this is actually an error path */
		knexthop_send_update(h);
	} else {
		if ((h = calloc(1, sizeof(struct knexthop))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		memcpy(&h->nexthop, addr, sizeof(h->nexthop));

		if (knexthop_insert(kt, h) == -1)
			return (-1);
	}

	return (0);
}

void
kr_nexthop_delete(u_int rtableid, struct bgpd_addr *addr)
{
	struct ktable		*kt;
	struct knexthop	*kn;

	if ((kt = ktable_get(rtableid)) == NULL) {
		log_warnx("%s: non-existent rtableid %d", __func__,
		    rtableid);
		return;
	}
	if ((kn = knexthop_find(kt, addr)) == NULL)
		return;

	knexthop_remove(kt, kn);
}

static struct ctl_show_interface *
kr_show_interface(struct kif *kif)
{
	static struct ctl_show_interface iface;

	bzero(&iface, sizeof(iface));
	strlcpy(iface.ifname, kif->ifname, sizeof(iface.ifname));

	snprintf(iface.linkstate, sizeof(iface.linkstate),
	    "%s", get_linkstate(kif->if_type, kif->link_state));

	snprintf(iface.media, sizeof(iface.media),
	    "%s", get_media_descr(kif->if_type));

	iface.baudrate = kif->baudrate;
	iface.rdomain = kif->rdomain;
	iface.nh_reachable = kif->nh_reachable;
	iface.is_up = (kif->flags & IFF_UP) == IFF_UP;

	return &iface;
}

const char *
get_linkstate(uint8_t if_type, int link_state)
{
	switch (link_state) {
	case LINK_STATE_DOWN:
		return ("down");
	case LINK_STATE_UP:
		return ("up");
	default:
		return ("unknown");
	}
}

const char *
get_media_descr(uint64_t media_type)
{
	switch (media_type) {
	case IFT_ETHER:
		return ("ethernet");
	case IFT_IPV4:
		return ("iptun4");
	case IFT_IPV6:
		return ("iptun6");
	case IFT_6TO4:
		return ("iptun6to4");
	case IFT_LOOP:
		return ("loopback");
	case IFT_FDDI:
		return ("fddi");
	case IFT_PPP:
		return ("ppp");
	case IFT_PROPVIRTUAL:
		return ("virtual");
	case IFT_PROPMUX:
		return ("vmux");
	case IFT_OTHER:
		return ("other");
	}
	return ("unknown");
}

void
kr_show_route(struct imsg *imsg)
{
	struct ktable		*kt;
	struct kroute_full	*kf;
	struct kroute		*kr, *kn;
	struct kroute6		*kr6, *kn6;
	struct bgpd_addr	*addr;
	int			 flags;
	sa_family_t		 af;
	struct ctl_show_nexthop	 snh;
	struct knexthop	*h;
	struct kif		*kif;
	u_int			 i;
	u_short			 ifindex = 0;

	switch (imsg->hdr.type) {
	case IMSG_CTL_KROUTE:
		if (imsg->hdr.len != IMSG_HEADER_SIZE + sizeof(flags) +
		    sizeof(af)) {
			log_warnx("%s: wrong imsg len", __func__);
			break;
		}
		kt = ktable_get(imsg->hdr.peerid);
		if (kt == NULL) {
			log_warnx("%s: table %u does not exist", __func__,
			    imsg->hdr.peerid);
			break;
		}
		memcpy(&flags, imsg->data, sizeof(flags));
		memcpy(&af, (char *)imsg->data + sizeof(flags), sizeof(af));
		if (!af || af == AF_INET)
			RB_FOREACH(kr, kroute_tree, &kt->krt) {
				if (flags && (kr->flags & flags) == 0)
					continue;
				kn = kr;
				do {
					kf = kr_tofull(kn);
					kf->priority = kr_priority(kf);
					send_imsg_session(IMSG_CTL_KROUTE,
					    imsg->hdr.pid, kf, sizeof(*kf));
				} while ((kn = kn->next) != NULL);
			}
		if (!af || af == AF_INET6)
			RB_FOREACH(kr6, kroute6_tree, &kt->krt6) {
				if (flags && (kr6->flags & flags) == 0)
					continue;
				kn6 = kr6;
				do {
					kf = kr6_tofull(kn6);
					kf->priority = kr_priority(kf);
					send_imsg_session(IMSG_CTL_KROUTE,
					    imsg->hdr.pid, kf, sizeof(*kf));
				} while ((kn6 = kn6->next) != NULL);
			}
		break;
	case IMSG_CTL_KROUTE_ADDR:
		if (imsg->hdr.len != IMSG_HEADER_SIZE +
		    sizeof(struct bgpd_addr)) {
			log_warnx("%s: wrong imsg len", __func__);
			break;
		}
		kt = ktable_get(imsg->hdr.peerid);
		if (kt == NULL) {
			log_warnx("%s: table %u does not exist", __func__,
			    imsg->hdr.peerid);
			break;
		}
		addr = imsg->data;
		kr = NULL;
		switch (addr->aid) {
		case AID_INET:
			kr = kroute_match(kt, addr, 1);
			if (kr != NULL) {
				kf = kr_tofull(kr);
				kf->priority = kr_priority(kf);
				send_imsg_session(IMSG_CTL_KROUTE,
				    imsg->hdr.pid, kf, sizeof(*kf));
			}
			break;
		case AID_INET6:
			kr6 = kroute6_match(kt, addr, 1);
			if (kr6 != NULL) {
				kf = kr6_tofull(kr6);
				kf->priority = kr_priority(kf);
				send_imsg_session(IMSG_CTL_KROUTE,
				    imsg->hdr.pid, kf, sizeof(*kf));
			}
			break;
		}
		break;
	case IMSG_CTL_SHOW_NEXTHOP:
		kt = ktable_get(imsg->hdr.peerid);
		if (kt == NULL) {
			log_warnx("%s: table %u does not exist", __func__,
			    imsg->hdr.peerid);
			break;
		}
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt)) {
			bzero(&snh, sizeof(snh));
			memcpy(&snh.addr, &h->nexthop, sizeof(snh.addr));
			if (h->kroute != NULL) {
				switch (h->nexthop.aid) {
				case AID_INET:
					kr = h->kroute;
					snh.valid = kroute_validate(kr);
					snh.krvalid = 1;
					snh.kr = *kr_tofull(kr);
					ifindex = kr->ifindex;
					break;
				case AID_INET6:
					kr6 = h->kroute;
					snh.valid = kroute6_validate(kr6);
					snh.krvalid = 1;
					snh.kr = *kr6_tofull(kr6);
					ifindex = kr6->ifindex;
					break;
				}
				snh.kr.priority = kr_priority(&snh.kr);
				if ((kif = kif_find(ifindex)) != NULL)
					memcpy(&snh.iface,
					    kr_show_interface(kif),
					    sizeof(snh.iface));
			}
			send_imsg_session(IMSG_CTL_SHOW_NEXTHOP, imsg->hdr.pid,
			    &snh, sizeof(snh));
		}
		break;
	case IMSG_CTL_SHOW_INTERFACE:
		RB_FOREACH(kif, kif_tree, &kit)
			send_imsg_session(IMSG_CTL_SHOW_INTERFACE,
			    imsg->hdr.pid, kr_show_interface(kif),
			    sizeof(struct ctl_show_interface));
		break;
	case IMSG_CTL_SHOW_FIB_TABLES:
		for (i = 0; i < krt_size; i++) {
			struct ktable	ktab;

			if ((kt = ktable_get(i)) == NULL)
				continue;

			ktab = *kt;
			/* do not leak internal information */
			RB_INIT(&ktab.krt);
			RB_INIT(&ktab.krt6);
			RB_INIT(&ktab.knt);
			TAILQ_INIT(&ktab.krn);

			send_imsg_session(IMSG_CTL_SHOW_FIB_TABLES,
			    imsg->hdr.pid, &ktab, sizeof(ktab));
		}
		break;
	default:	/* nada */
		break;
	}

	send_imsg_session(IMSG_CTL_END, imsg->hdr.pid, NULL, 0);
}

static void
kr_send_dependon(struct kif *kif)
{
	struct session_dependon sdon = { {0} };

	strlcpy(sdon.ifname, kif->ifname, sizeof(sdon.ifname));
	sdon.depend_state = kif->depend_state;
	send_imsg_session(IMSG_SESSION_DEPENDON, 0, &sdon, sizeof(sdon));
}

void
kr_ifinfo(char *ifname)
{
	struct kif	*kif;

	RB_FOREACH(kif, kif_tree, &kit)
		if (!strcmp(ifname, kif->ifname)) {
			kr_send_dependon(kif);
			return;
		}
}

void
kr_net_delete(struct network *n)
{
	filterset_free(&n->net.attrset);
	free(n);
}

uint8_t
kr_priority(struct kroute_full *kf)
{
	if (kf->priority == RTP_BGP)
		return (kr_state.fib_prio);
	return (kf->priority);
}

static int
kr_net_redist_add(struct ktable *kt, struct network_config *net,
    struct filter_set_head *attr, int dynamic)
{
	struct kredist_node *r, *xr;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal("%s", __func__);
	r->prefix = net->prefix;
	r->prefixlen = net->prefixlen;
	r->rd = net->rd;
	r->dynamic = dynamic;

	xr = RB_INSERT(kredist_tree, &kt->kredist, r);
	if (xr != NULL) {
		free(r);

		if (dynamic != xr->dynamic && dynamic) {
			/*
			 * ignore update a non-dynamic announcement is
			 * already present which has preference.
			 */
			return 0;
		}
		/*
		 * only equal or non-dynamic announcement ends up here.
		 * In both cases reset the dynamic flag (nop for equal) and
		 * redistribute.
		 */
		xr->dynamic = dynamic;
	}

	if (send_network(IMSG_NETWORK_ADD, net, attr) == -1)
		log_warnx("%s: faild to send network update", __func__);
	return 1;
}

static void
kr_net_redist_del(struct ktable *kt, struct network_config *net, int dynamic)
{
	struct kredist_node *r, node;

	bzero(&node, sizeof(node));
	node.prefix = net->prefix;
	node.prefixlen = net->prefixlen;
	node.rd = net->rd;

	r = RB_FIND(kredist_tree, &kt->kredist, &node);
	if (r == NULL || dynamic != r->dynamic)
		return;

	if (RB_REMOVE(kredist_tree, &kt->kredist, r) == NULL) {
		log_warnx("%s: failed to remove network %s/%u", __func__,
		    log_addr(&node.prefix), node.prefixlen);
		return;
	}
	free(r);

	if (send_network(IMSG_NETWORK_REMOVE, net, NULL) == -1)
		log_warnx("%s: faild to send network removal", __func__);
}

int
kr_net_match(struct ktable *kt, struct network_config *net, u_int16_t flags,
    int loopback)
{
	struct network		*xn;

	TAILQ_FOREACH(xn, &kt->krn, entry) {
		if (xn->net.prefix.aid != net->prefix.aid)
			continue;
		switch (xn->net.type) {
		case NETWORK_DEFAULT:
			/* static match already redistributed */
			continue;
		case NETWORK_STATIC:
			/* Skip networks with nexthop on loopback. */
			if (loopback)
				continue;
			if (flags & F_STATIC)
				break;
			continue;
		case NETWORK_CONNECTED:
			/* Skip networks with nexthop on loopback. */
			if (loopback)
				continue;
			if (flags & F_CONNECTED)
				break;
			continue;
		case NETWORK_RTLABEL:
			break;
		case NETWORK_PRIORITY:
			if (net->priority == xn->net.priority)
				break;
			continue;
		case NETWORK_MRTCLONE:
		case NETWORK_PREFIXSET:
			/* must not happen */
			log_warnx("%s: found a NETWORK_PREFIXSET, "
			    "please send a bug report", __func__);
			continue;
		}

		net->rd = xn->net.rd;
		if (kr_net_redist_add(kt, net, &xn->net.attrset, 1))
			return (1);
	}
	return (0);
}

struct network *
kr_net_find(struct ktable *kt, struct network *n)
{
	struct network		*xn;

	TAILQ_FOREACH(xn, &kt->krn, entry) {
		if (n->net.type != xn->net.type ||
		    n->net.prefixlen != xn->net.prefixlen ||
		    n->net.rd != xn->net.rd)
			continue;
		if (memcmp(&n->net.prefix, &xn->net.prefix,
		    sizeof(n->net.prefix)) == 0)
			return (xn);
	}
	return (NULL);
}

void
kr_net_reload(u_int rtableid, u_int64_t rd, struct network_head *nh)
{
	struct network		*n, *xn;
	struct ktable		*kt;

	if ((kt = ktable_get(rtableid)) == NULL)
		fatalx("%s: non-existent rtableid %d", __func__, rtableid);

	while ((n = TAILQ_FIRST(nh)) != NULL) {
		TAILQ_REMOVE(nh, n, entry);
		n->net.old = 0;
		n->net.rd = rd;
		xn = kr_net_find(kt, n);
		if (xn) {
			xn->net.old = 0;
			filterset_free(&xn->net.attrset);
			filterset_move(&n->net.attrset, &xn->net.attrset);
			kr_net_delete(n);
		} else
			TAILQ_INSERT_TAIL(&kt->krn, n, entry);
	}
}

void
kr_net_clear(struct ktable *kt)
{
	struct network *n, *xn;

	TAILQ_FOREACH_SAFE(n, &kt->krn, entry, xn) {
		TAILQ_REMOVE(&kt->krn, n, entry);
		if (n->net.type == NETWORK_DEFAULT)
			kr_net_redist_del(kt, &n->net, 0);
		kr_net_delete(n);
	}
}

void
kr_redistribute(int type, struct ktable *kt, struct kroute *kr)
{
	struct network_config	 net;
	u_int32_t		 a;
	int			 loflag = 0;

	bzero(&net, sizeof(net));
	net.prefix.aid = AID_INET;
	net.prefix.v4.s_addr = kr->prefix.s_addr;
	net.prefixlen = kr->prefixlen;
	net.rtlabel = kr->labelid;
	net.priority = kr->priority;

	/* shortcut for removals */
	if (type == IMSG_NETWORK_REMOVE) {
		kr_net_redist_del(kt, &net, 1);
		return;
	}

	if (kr->flags & F_BGPD)
		return;

	/*
	 * We consider the loopback net, multicast and experimental addresses
	 * as not redistributable.
	 */
	a = ntohl(kr->prefix.s_addr);
	if (IN_MULTICAST(a) || IN_BADCLASS(a) ||
	    (a >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)
		return;

	/* Check if the nexthop is the loopback addr. */
	if (kr->nexthop.s_addr == htonl(INADDR_LOOPBACK))
		loflag = 1;

	/*
	 * never allow 0.0.0.0/0 the default route can only be redistributed
	 * with announce default.
	 */
	if (kr->prefix.s_addr == INADDR_ANY && kr->prefixlen == 0)
		return;

	if (kr_net_match(kt, &net, kr->flags, loflag) == 0)
		/* no longer matches, if still present remove it */
		kr_net_redist_del(kt, &net, 1);
}

void
kr_redistribute6(int type, struct ktable *kt, struct kroute6 *kr6)
{
	struct network_config	net;
	int			loflag = 0;

	bzero(&net, sizeof(net));
	net.prefix.aid = AID_INET6;
	memcpy(&net.prefix.v6, &kr6->prefix, sizeof(struct in6_addr));
	net.prefixlen = kr6->prefixlen;
	net.rtlabel = kr6->labelid;
	net.priority = kr6->priority;

	/* shortcut for removals */
	if (type == IMSG_NETWORK_REMOVE) {
		kr_net_redist_del(kt, &net, 1);
		return;
	}

	if (kr6->flags & F_BGPD)
		return;

	/*
	 * We consider unspecified, loopback, multicast, link- and site-local,
	 * IPv4 mapped and IPv4 compatible addresses as not redistributable.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&kr6->prefix) ||
	    IN6_IS_ADDR_LOOPBACK(&kr6->prefix) ||
	    IN6_IS_ADDR_MULTICAST(&kr6->prefix) ||
	    IN6_IS_ADDR_LINKLOCAL(&kr6->prefix) ||
	    IN6_IS_ADDR_SITELOCAL(&kr6->prefix) ||
	    IN6_IS_ADDR_V4MAPPED(&kr6->prefix) ||
	    IN6_IS_ADDR_V4COMPAT(&kr6->prefix))
		return;

	/* Check if the nexthop is the loopback addr. */
	if (IN6_IS_ADDR_LOOPBACK(&kr6->nexthop))
		loflag = 1;

	/*
	 * never allow ::/0 the default route can only be redistributed
	 * with announce default.
	 */
	if (kr6->prefixlen == 0 &&
	    memcmp(&kr6->prefix, &in6addr_any, sizeof(struct in6_addr)) == 0)
		return;

	if (kr_net_match(kt, &net, kr6->flags, loflag) == 0)
		/* no longer matches, if still present remove it */
		kr_net_redist_del(kt, &net, 1);
}

void
ktable_preload(void)
{
	struct ktable	*kt;
	struct network	*n;
	u_int		 i;

	for (i = 0; i < krt_size; i++) {
		if ((kt = ktable_get(i)) == NULL)
			continue;
		kt->state = RECONF_DELETE;

		/* mark all networks as old */
		TAILQ_FOREACH(n, &kt->krn, entry)
			n->net.old = 1;
	}
}

void
ktable_postload(void)
{
	struct ktable	*kt;
	struct network	*n, *xn;
	u_int		 i;

	for (i = krt_size; i > 0; i--) {
		if ((kt = ktable_get(i - 1)) == NULL)
			continue;
		if (kt->state == RECONF_DELETE) {
			ktable_free(i - 1);
			continue;
		} else if (kt->state == RECONF_REINIT)
			kt->fib_sync = kt->fib_conf;

		/* cleanup old networks */
		TAILQ_FOREACH_SAFE(n, &kt->krn, entry, xn) {
			if (n->net.old) {
				TAILQ_REMOVE(&kt->krn, n, entry);
				if (n->net.type == NETWORK_DEFAULT)
					kr_net_redist_del(kt, &n->net, 0);
				kr_net_delete(n);
			}
		}
	}
}

int
kr_reload(void)
{
	struct ktable		*kt;
	struct kroute	*kr;
	struct kroute6	*kr6;
	struct knexthop	*nh;
	struct network		*n;
	u_int			 rid;
	int			 hasdyn = 0;

	for (rid = 0; rid < krt_size; rid++) {
		if ((kt = ktable_get(rid)) == NULL)
			continue;

		/* if this is the main nexthop table revalidate nexthops */
		if (kt->rtableid == kt->nhtableid)
			RB_FOREACH(nh, knexthop_tree, KT2KNT(kt))
				knexthop_validate(kt, nh);

		TAILQ_FOREACH(n, &kt->krn, entry)
			if (n->net.type == NETWORK_DEFAULT) {
				kr_net_redist_add(kt, &n->net,
				    &n->net.attrset, 0);
			} else
				hasdyn = 1;

		if (hasdyn) {
			/* only evaluate the full tree if we need */
			RB_FOREACH(kr, kroute_tree, &kt->krt)
				kr_redistribute(IMSG_NETWORK_ADD, kt, kr);
			RB_FOREACH(kr6, kroute6_tree, &kt->krt6)
				kr_redistribute6(IMSG_NETWORK_ADD, kt, kr6);
		}
	}

	return (0);
}

struct kroute_full *
kr_tofull(struct kroute *kr)
{
	static struct kroute_full	kf;

	bzero(&kf, sizeof(kf));

	kf.prefix.aid = AID_INET;
	kf.prefix.v4.s_addr = kr->prefix.s_addr;
	kf.nexthop.aid = AID_INET;
	kf.nexthop.v4.s_addr = kr->nexthop.s_addr;
	strlcpy(kf.label, rtlabel_id2name(kr->labelid), sizeof(kf.label));
	kf.flags = kr->flags;
	kf.ifindex = kr->ifindex;
	kf.prefixlen = kr->prefixlen;
	kf.priority = kr->priority;

	return (&kf);
}

struct kroute_full *
kr6_tofull(struct kroute6 *kr6)
{
	static struct kroute_full	kf;

	bzero(&kf, sizeof(kf));

	kf.prefix.aid = AID_INET6;
	memcpy(&kf.prefix.v6, &kr6->prefix, sizeof(struct in6_addr));
	kf.nexthop.aid = AID_INET6;
	memcpy(&kf.nexthop.v6, &kr6->nexthop, sizeof(struct in6_addr));
	strlcpy(kf.label, rtlabel_id2name(kr6->labelid), sizeof(kf.label));
	kf.flags = kr6->flags;
	kf.ifindex = kr6->ifindex;
	kf.prefixlen = kr6->prefixlen;
	kf.priority = kr6->priority;

	return (&kf);
}

/*
 * RB-tree compare functions
 */

int
kroute_compare(struct kroute *a, struct kroute *b)
{
	if (ntohl(a->prefix.s_addr) < ntohl(b->prefix.s_addr))
		return (-1);
	if (ntohl(a->prefix.s_addr) > ntohl(b->prefix.s_addr))
		return (1);
	if (a->prefixlen < b->prefixlen)
		return (-1);
	if (a->prefixlen > b->prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->priority == RTP_ANY || b->priority == RTP_ANY)
		return (0);
	if (a->priority < b->priority)
		return (-1);
	if (a->priority > b->priority)
		return (1);
	return (0);
}

int
kroute6_compare(struct kroute6 *a, struct kroute6 *b)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (a->prefix.s6_addr[i] < b->prefix.s6_addr[i])
			return (-1);
		if (a->prefix.s6_addr[i] > b->prefix.s6_addr[i])
			return (1);
	}

	if (a->prefixlen < b->prefixlen)
		return (-1);
	if (a->prefixlen > b->prefixlen)
		return (1);

	/* if the priority is RTP_ANY finish on the first address hit */
	if (a->priority == RTP_ANY || b->priority == RTP_ANY)
		return (0);
	if (a->priority < b->priority)
		return (-1);
	if (a->priority > b->priority)
		return (1);
	return (0);
}

int
knexthop_compare(struct knexthop *a, struct knexthop *b)
{
	int	i;

	if (a->nexthop.aid != b->nexthop.aid)
		return (b->nexthop.aid - a->nexthop.aid);

	switch (a->nexthop.aid) {
	case AID_INET:
		if (ntohl(a->nexthop.v4.s_addr) < ntohl(b->nexthop.v4.s_addr))
			return (-1);
		if (ntohl(a->nexthop.v4.s_addr) > ntohl(b->nexthop.v4.s_addr))
			return (1);
		break;
	case AID_INET6:
		for (i = 0; i < 16; i++) {
			if (a->nexthop.v6.s6_addr[i] < b->nexthop.v6.s6_addr[i])
				return (-1);
			if (a->nexthop.v6.s6_addr[i] > b->nexthop.v6.s6_addr[i])
				return (1);
		}
		break;
	default:
		fatalx("%s: unknown AF", __func__);
	}

	return (0);
}

int
kredist_compare(struct kredist_node *a, struct kredist_node *b)
{
	int	i;

	if (a->prefix.aid != b->prefix.aid)
		return (b->prefix.aid - a->prefix.aid);

	if (a->prefixlen < b->prefixlen)
		return (-1);
	if (a->prefixlen > b->prefixlen)
		return (1);

	switch (a->prefix.aid) {
	case AID_INET:
		if (ntohl(a->prefix.v4.s_addr) < ntohl(b->prefix.v4.s_addr))
			return (-1);
		if (ntohl(a->prefix.v4.s_addr) > ntohl(b->prefix.v4.s_addr))
			return (1);
		break;
	case AID_INET6:
		for (i = 0; i < 16; i++) {
			if (a->prefix.v6.s6_addr[i] < b->prefix.v6.s6_addr[i])
				return (-1);
			if (a->prefix.v6.s6_addr[i] > b->prefix.v6.s6_addr[i])
				return (1);
		}
		break;
	default:
		fatalx("%s: unknown AF", __func__);
	}

	if (a->rd < b->rd)
		return (-1);
	if (a->rd > b->rd)
		return (1);

	return (0);
}

int
kif_compare(struct kif *a, struct kif *b)
{
	return (b->ifindex - a->ifindex);
}


/*
 * tree management functions
 */

struct kroute *
kroute_find(struct ktable *kt, struct in_addr prefix, uint8_t prefixlen,
    uint8_t prio)
{
	struct kroute	 s;
	struct kroute	*kn, *tmp;

	s.prefix = prefix;
	s.prefixlen = prefixlen;
	s.priority = prio;

	kn = RB_FIND(kroute_tree, &kt->krt, &s);
	if (kn && prio == RTP_ANY) {
		tmp = RB_PREV(kroute_tree, &kt->krt, kn);
		while (tmp) {
			if (kroute_compare(&s, tmp) == 0)
				kn = tmp;
			else
				break;
			tmp = RB_PREV(kroute_tree, &kt->krt, kn);
		}
	}
	return (kn);
}

struct kroute *
kroute_matchgw(struct kroute *kr, struct sockaddr_in *sa_in)
{
	struct in_addr	nexthop;

	if (sa_in == NULL) {
		log_warnx("%s: no nexthop defined", __func__);
		return (NULL);
	}
	nexthop = sa_in->sin_addr;

	while (kr) {
		if (kr->nexthop.s_addr == nexthop.s_addr)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}


int
kroute_insert(struct ktable *kt, struct kroute *kr)
{
	struct kroute	*krm;

	if ((krm = RB_INSERT(kroute_tree, &kt->krt, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}
	return (kroute_post_insert(kt, kr, krm));
}

static in_addr_t
prefixlen2mask(uint8_t prefixlen)
{
	if (prefixlen == 0)
		return (0);

	return (0xffffffff << (32 - prefixlen));
}

int
kroute_post_insert(struct ktable *kt, struct kroute *kr,
    struct kroute *krm)
{
	struct knexthop	*h;
	in_addr_t		 mask, ina;

	/* XXX this is wrong for nexthop validated via BGP */
	if (!(kr->flags & F_BGPD)) {
		mask = prefixlen2mask(kr->prefixlen);
		ina = ntohl(kr->prefix.s_addr);
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt))
			if (h->nexthop.aid == AID_INET &&
			    (ntohl(h->nexthop.v4.s_addr) & mask) == ina)
				knexthop_validate(kt, h);

		if (kr->flags & F_CONNECTED)
			if (kif_kr_insert(kr) == -1)
				return (-1);

		if (krm == NULL)
			/* redistribute multipath routes only once */
			kr_redistribute(IMSG_NETWORK_ADD, kt, kr);
	}
	return (0);
}


int
kroute_remove(struct ktable *kt, struct kroute *kr)
{
	struct kroute	*krm;
	struct knexthop	*s;

	if ((krm = RB_FIND(kroute_tree, &kt->krt, kr)) == NULL) {
		log_warnx("%s: failed to find %s/%u", __func__,
		    inet_ntoa(kr->prefix), kr->prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute_tree, &kt->krt, kr) == NULL) {
			log_warnx("%s: failed for %s/%u", __func__,
			    inet_ntoa(kr->prefix), kr->prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute_tree, &kt->krt, kr->next) !=
			    NULL) {
				log_warnx("%s: failed to add %s/%u", __func__,
				    inet_ntoa(kr->prefix), kr->prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("%s: multipath list corrupted "
			    "for %s/%u", inet_ntoa(kr->prefix), __func__,
			    kr->prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	/* check whether a nexthop depends on this kroute */
	if (kr->flags & F_NEXTHOP)
		RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
			if (s->kroute == kr)
				knexthop_validate(kt, s);

	if (!(kr->flags & F_BGPD) && kr == krm && kr->next == NULL)
		/* again remove only once */
		kr_redistribute(IMSG_NETWORK_REMOVE, kt, kr);

	if (kr->flags & F_CONNECTED)
		if (kif_kr_remove(kr) == -1) {
			free(kr);
			return (-1);
		}

	free(kr);
	return (0);
}

void
kroute_clear(struct ktable *kt)
{
	struct kroute	*kr;

	while ((kr = RB_MIN(kroute_tree, &kt->krt)) != NULL)
		kroute_remove(kt, kr);
}

struct kroute6 *
kroute6_find(struct ktable *kt, const struct in6_addr *prefix,
    u_int8_t prefixlen, u_int8_t prio)
{
	struct kroute6	s;
	struct kroute6	*kn6, *tmp;

	memcpy(&s.prefix, prefix, sizeof(struct in6_addr));
	s.prefixlen = prefixlen;
	s.priority = prio;

	kn6 = RB_FIND(kroute6_tree, &kt->krt6, &s);
	if (kn6 && prio == RTP_ANY) {
		tmp = RB_PREV(kroute6_tree, &kt->krt6, kn6);
		while (tmp) {
			if (kroute6_compare(&s, tmp) == 0)
				kn6 = tmp;
			else
				break;
			tmp = RB_PREV(kroute6_tree, &kt->krt6, kn6);
		}
	}
	return (kn6);
}

struct kroute6 *
kroute6_matchgw(struct kroute6 *kr, struct sockaddr_in6 *sa_in6)
{
	struct in6_addr	nexthop;

	if (sa_in6 == NULL) {
		log_warnx("%s: no nexthop defined", __func__);
		return (NULL);
	}
	memcpy(&nexthop, &sa_in6->sin6_addr, sizeof(nexthop));

	while (kr) {
		if (memcmp(&kr->nexthop, &nexthop, sizeof(nexthop)) == 0)
			return (kr);
		kr = kr->next;
	}

	return (NULL);
}

int
kroute6_insert(struct ktable *kt, struct kroute6 *kr)
{
	struct kroute6	*krm;
	struct knexthop	*h;
	struct in6_addr		 ina, inb;

	if ((krm = RB_INSERT(kroute6_tree, &kt->krt6, kr)) != NULL) {
		/* multipath route, add at end of list */
		while (krm->next != NULL)
			krm = krm->next;
		krm->next = kr;
		kr->next = NULL; /* to be sure */
	}

	/* XXX this is wrong for nexthop validated via BGP */
	if (!(kr->flags & F_BGPD)) {
		inet6applymask(&ina, &kr->prefix, kr->prefixlen);
		RB_FOREACH(h, knexthop_tree, KT2KNT(kt))
			if (h->nexthop.aid == AID_INET6) {
				inet6applymask(&inb, &h->nexthop.v6,
				    kr->prefixlen);
				if (memcmp(&ina, &inb, sizeof(ina)) == 0)
					knexthop_validate(kt, h);
			}

		if (kr->flags & F_CONNECTED)
			if (kif_kr6_insert(kr) == -1)
				return (-1);

		if (krm == NULL)
			/* redistribute multipath routes only once */
			kr_redistribute6(IMSG_NETWORK_ADD, kt, kr);
	}

	return (0);
}

int
kroute6_remove(struct ktable *kt, struct kroute6 *kr)
{
	struct kroute6	*krm;
	struct knexthop	*s;

	if ((krm = RB_FIND(kroute6_tree, &kt->krt6, kr)) == NULL) {
		log_warnx("%s: failed for %s/%u", __func__,
		    log_in6addr(&kr->prefix), kr->prefixlen);
		return (-1);
	}

	if (krm == kr) {
		/* head element */
		if (RB_REMOVE(kroute6_tree, &kt->krt6, kr) == NULL) {
			log_warnx("%s: failed for %s/%u", __func__,
			    log_in6addr(&kr->prefix), kr->prefixlen);
			return (-1);
		}
		if (kr->next != NULL) {
			if (RB_INSERT(kroute6_tree, &kt->krt6, kr->next) !=
			    NULL) {
				log_warnx("%s: failed to add %s/%u", __func__,
				    log_in6addr(&kr->prefix),
				    kr->prefixlen);
				return (-1);
			}
		}
	} else {
		/* somewhere in the list */
		while (krm->next != kr && krm->next != NULL)
			krm = krm->next;
		if (krm->next == NULL) {
			log_warnx("%s: multipath list corrupted "
			    "for %s/%u", __func__, log_in6addr(&kr->prefix),
			    kr->prefixlen);
			return (-1);
		}
		krm->next = kr->next;
	}

	/* check whether a nexthop depends on this kroute */
	if (kr->flags & F_NEXTHOP)
		RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
			if (s->kroute == kr)
				knexthop_validate(kt, s);

	if (!(kr->flags & F_BGPD) && kr == krm && kr->next == NULL)
		/* again remove only once */
		kr_redistribute6(IMSG_NETWORK_REMOVE, kt, kr);

	if (kr->flags & F_CONNECTED)
		if (kif_kr6_remove(kr) == -1) {
			free(kr);
			return (-1);
		}

	free(kr);
	return (0);
}

void
kroute6_clear(struct ktable *kt)
{
	struct kroute6	*kr;

	while ((kr = RB_MIN(kroute6_tree, &kt->krt6)) != NULL)
		kroute6_remove(kt, kr);
}

struct knexthop *
knexthop_find(struct ktable *kt, struct bgpd_addr *addr)
{
	struct knexthop	s;

	bzero(&s, sizeof(s));
	memcpy(&s.nexthop, addr, sizeof(s.nexthop));

	return (RB_FIND(knexthop_tree, KT2KNT(kt), &s));
}

int
knexthop_insert(struct ktable *kt, struct knexthop *kn)
{
	if (RB_INSERT(knexthop_tree, KT2KNT(kt), kn) != NULL) {
		log_warnx("%s: failed for %s", __func__,
		    log_addr(&kn->nexthop));
		free(kn);
		return (-1);
	}

	knexthop_validate(kt, kn);

	return (0);
}

int
knexthop_remove(struct ktable *kt, struct knexthop *kn)
{
	kroute_detach_nexthop(kt, kn);

	if (RB_REMOVE(knexthop_tree, KT2KNT(kt), kn) == NULL) {
		log_warnx("%s: failed for %s", __func__,
		    log_addr(&kn->nexthop));
		return (-1);
	}

	free(kn);
	return (0);
}

void
knexthop_clear(struct ktable *kt)
{
	struct knexthop	*kn;

	while ((kn = RB_MIN(knexthop_tree, KT2KNT(kt))) != NULL)
		knexthop_remove(kt, kn);
}

struct kif *
kif_find(int ifindex)
{
	struct kif	s;

	bzero(&s, sizeof(s));
	s.ifindex = ifindex;

	return (RB_FIND(kif_tree, &kit, &s));
}

int
kif_insert(struct kif *kif)
{
	LIST_INIT(&kif->kroute_l);
	LIST_INIT(&kif->kroute6_l);

	if (RB_INSERT(kif_tree, &kit, kif) != NULL) {
		log_warnx("RB_INSERT(kif_tree, &kit, kif)");
		free(kif);
		return (-1);
	}

	return (0);
}

int
kif_remove(struct kif *kif)
{
	struct ktable	*kt;
	struct kif_kr	*kkr;
	struct kif_kr6	*kkr6;

	if (RB_REMOVE(kif_tree, &kit, kif) == NULL) {
		log_warnx("RB_REMOVE(kif_tree, &kit, kif)");
		return (-1);
	}

	if ((kt = ktable_get(kif->rdomain)) == NULL)
		goto done;

	while ((kkr = LIST_FIRST(&kif->kroute_l)) != NULL) {
		LIST_REMOVE(kkr, entry);
		kkr->kr->flags &= ~F_NEXTHOP;
		kroute_remove(kt, kkr->kr);
		free(kkr);
	}

	while ((kkr6 = LIST_FIRST(&kif->kroute6_l)) != NULL) {
		LIST_REMOVE(kkr6, entry);
		kkr6->kr->flags &= ~F_NEXTHOP;
		kroute6_remove(kt, kkr6->kr);
		free(kkr6);
	}
done:
	free(kif);
	return (0);
}

void
kif_clear(void)
{
	struct kif	*kif;

	while ((kif = RB_MIN(kif_tree, &kit)) != NULL)
		kif_remove(kif);
}

int
kif_kr_insert(struct kroute *kr)
{
	struct kif	*kif;
	struct kif_kr	*kkr;
	int		 rc;

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->ifindex);
		return (0);
	}

	if (kr->kif != NULL && kr->kif != kif) {
		if ((rc = kif_kr_remove(kr)) == -1)
			return (rc);
	}

	if (kr->kif == NULL) {
		if ((kkr = calloc(1, sizeof(struct kif_kr))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		kr->kif = kif;
		kkr->kr = kr;
		LIST_INSERT_HEAD(&kif->kroute_l, kkr, entry);
	}

	return (0);
}

int
kif_kr_remove(struct kroute *kr)
{
	struct kif	*kif;
	struct kif_kr	*kkr;

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->ifindex);
		return (0);
	}

	for (kkr = LIST_FIRST(&kif->kroute_l); kkr != NULL && kkr->kr != kr;
	    kkr = LIST_NEXT(kkr, entry))
		;	/* nothing */

	if (kkr == NULL) {
		log_warnx("%s: can't remove connected route from interface "
		    "with index %u: not found", __func__, kr->ifindex);
		return (-1);
	}

	LIST_REMOVE(kkr, entry);
	free(kkr);

	kr->kif = NULL;

	return (0);
}

int
kif_kr6_insert(struct kroute6 *kr)
{
	struct kif	*kif;
	struct kif_kr6	*kkr6;
	int		 rc;

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->ifindex);
		return (0);
	}

	if (kr->kif != NULL && kr->kif != kif) {
		if ((rc = kif_kr6_remove(kr)) == -1)
			return (rc);
	}

	if (kr->kif == NULL) {
		if ((kkr6 = calloc(1, sizeof(struct kif_kr6))) == NULL) {
			log_warn("%s", __func__);
			return (-1);
		}
		kr->kif = kif;
		kkr6->kr = kr;
		LIST_INSERT_HEAD(&kif->kroute6_l, kkr6, entry);
	}

	return (0);
}

int
kif_kr6_remove(struct kroute6 *kr)
{
	struct kif	*kif;
	struct kif_kr6	*kkr6;

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %u not found",
			    __func__, kr->ifindex);
		return (0);
	}

	for (kkr6 = LIST_FIRST(&kif->kroute6_l); kkr6 != NULL && kkr6->kr != kr;
	    kkr6 = LIST_NEXT(kkr6, entry))
		;	/* nothing */

	if (kkr6 == NULL) {
		log_warnx("%s: can't remove connected route from interface "
		    "with index %u: not found", __func__, kr->ifindex);
		return (-1);
	}

	LIST_REMOVE(kkr6, entry);
	free(kkr6);

	kr->kif = NULL;

	return (0);
}

/*
 * nexthop validation
 */

static int
kif_validate(struct kif *kif)
{
	if (!(kif->flags & IFF_UP))
		return (0);

	/*
	 * we treat link_state == LINK_STATE_UNKNOWN as valid,
	 * not all interfaces have a concept of "link state" and/or
	 * do not report up
	 */

	if (kif->link_state == LINK_STATE_DOWN)
		return (0);

	return (1);
}

/*
 * return 1 when the interface is up and the link state is up or unknwown
 * except when this is a carp interface, then return 1 only when link state
 * is up
 */
static int
kif_depend_state(struct kif *kif)
{
	if (!(kif->flags & IFF_UP))
		return (0);

	return (kif->link_state == LINK_STATE_UP);
}


int
kroute_validate(struct kroute *kr)
{
	struct kif		*kif;

	if (kr->flags & (F_REJECT | F_BLACKHOLE))
		return (0);

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %d not found, "
			    "referenced from route for %s/%u", __func__,
			    kr->ifindex, inet_ntoa(kr->prefix),
			    kr->prefixlen);
		return (1);
	}

	return (kif->nh_reachable);
}

int
kroute6_validate(struct kroute6 *kr)
{
	struct kif		*kif;

	if (kr->flags & (F_REJECT | F_BLACKHOLE))
		return (0);

	if ((kif = kif_find(kr->ifindex)) == NULL) {
		if (kr->ifindex)
			log_warnx("%s: interface with index %d not found, "
			    "referenced from route for %s/%u", __func__,
			    kr->ifindex, log_in6addr(&kr->prefix),
			    kr->prefixlen);
		return (1);
	}

	return (kif->nh_reachable);
}

void
knexthop_track(struct ktable *kt, u_short ifindex)
{
	struct knexthop	*kn;

	RB_FOREACH(kn, knexthop_tree, KT2KNT(kt)) {
		if (kn->ifindex == ifindex)
			knexthop_validate(kt, kn);
	}
}

void
knexthop_validate(struct ktable *kt, struct knexthop *kn)
{
	void		*oldk;
	struct kroute	*kr;
	struct kroute6	*kr6;

	oldk = kn->kroute;
	kroute_detach_nexthop(kt, kn);

	if ((kt = ktable_get(kt->nhtableid)) == NULL)
		fatalx("%s: lost nexthop routing table", __func__);

	switch (kn->nexthop.aid) {
	case AID_INET:
		kr = kroute_match(kt, &kn->nexthop, 0);

		if (kr != NULL) {
			kn->kroute = kr;
			kn->ifindex = kr->ifindex;
			kr->flags |= F_NEXTHOP;
		}

		/*
		 * Send update if nexthop route changed under us if
		 * the route remains the same then the NH state has not
		 * changed.
		 */
		if (kr != oldk)
			knexthop_send_update(kn);
		break;
	case AID_INET6:
		kr6 = kroute6_match(kt, &kn->nexthop, 0);

		if (kr6 != NULL) {
			kn->kroute = kr6;
			kn->ifindex = kr6->ifindex;
			kr6->flags |= F_NEXTHOP;
		}

		if (kr6 != oldk)
			knexthop_send_update(kn);
		break;
	}
}

void
knexthop_update(struct ktable *kt, struct kroute_full *kf)
{
	struct knexthop	*kn;

	RB_FOREACH(kn, knexthop_tree, KT2KNT(kt))
		if (prefix_compare(&kf->prefix, &kn->nexthop,
		    kf->prefixlen) == 0)
			knexthop_send_update(kn);
}

void
knexthop_send_update(struct knexthop *kn)
{
	struct kroute_nexthop	 n;
	struct kroute		*kr;
	struct kroute6		*kr6;

	memset(&n, 0, sizeof(n));
	n.nexthop = kn->nexthop;

	if (kn->kroute == NULL) {
		n.valid = 0;	/* NH is not valid */
		send_nexthop_update(&n);
		return;
	}

	switch (kn->nexthop.aid) {
	case AID_INET:
		kr = kn->kroute;
		n.valid = kroute_validate(kr);
		n.connected = kr->flags & F_CONNECTED;
		if (!n.connected) {
			n.gateway.aid = AID_INET;
			n.gateway.v4.s_addr = kr->nexthop.s_addr;
		} else {
			n.gateway = n.nexthop;
			n.net.aid = AID_INET;
			n.net.v4.s_addr = kr->prefix.s_addr;
			n.netlen = kr->prefixlen;
		}
		break;
	case AID_INET6:
		kr6 = kn->kroute;
		n.valid = kroute6_validate(kr6);
		n.connected = kr6->flags & F_CONNECTED;
		if (!n.connected) {
			n.gateway.aid = AID_INET6;
			n.gateway.v6 = kr6->nexthop;
			n.gateway.scope_id = kr6->nexthop_scope_id;
		} else {
			n.gateway = n.nexthop;
			n.net.aid = AID_INET6;
			n.net.v6 = kr6->prefix;
			n.net.scope_id = kr6->prefix_scope_id;
			n.netlen = kr6->prefixlen;
		}
		break;
	}
	send_nexthop_update(&n);
}

struct kroute *
kroute_match(struct ktable *kt, struct bgpd_addr *key, int matchany)
{
	int			 i;
	struct kroute		*kr;
	struct bgpd_addr	 masked;

	for (i = 32; i >= 0; i--) {
		applymask(&masked, key, i);
		if ((kr = kroute_find(kt, masked.v4, i, RTP_ANY)) != NULL)
			if (matchany || bgpd_oknexthop(kr_tofull(kr)))
				return (kr);
	}

	return (NULL);
}

struct kroute6 *
kroute6_match(struct ktable *kt, struct bgpd_addr *key, int matchany)
{
	int			 i;
	struct kroute6		*kr6;
	struct bgpd_addr	 masked;

	for (i = 128; i >= 0; i--) {
		applymask(&masked, key, i);
		if ((kr6 = kroute6_find(kt, &masked.v6, i, RTP_ANY)) != NULL)
			if (matchany || bgpd_oknexthop(kr6_tofull(kr6)))
				return (kr6);
	}

	return (NULL);
}

void
kroute_detach_nexthop(struct ktable *kt, struct knexthop *kn)
{
	struct knexthop	*s;
	struct kroute	*k;
	struct kroute6	*k6;

	if (kn->kroute == NULL)
		return;

	/*
	 * check whether there's another nexthop depending on this kroute
	 * if not remove the flag
	 */
	RB_FOREACH(s, knexthop_tree, KT2KNT(kt))
		if (s->kroute == kn->kroute && s != kn)
			break;

	if (s == NULL) {
		switch (kn->nexthop.aid) {
		case AID_INET:
			k = kn->kroute;
			k->flags &= ~F_NEXTHOP;
			break;
		case AID_INET6:
			k6 = kn->kroute;
			k6->flags &= ~F_NEXTHOP;
			break;
		}
	}

	kn->kroute = NULL;
}

/*
 * misc helpers
 */

int
protect_lo(struct ktable *kt)
{
	struct kroute	*kr;
	struct kroute6	*kr6;

	/* special protection for 127/8 */
	if ((kr = calloc(1, sizeof(struct kroute))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	kr->prefix.s_addr = htonl(INADDR_LOOPBACK & IN_CLASSA_NET);
	kr->prefixlen = 8;
	kr->flags = F_CONNECTED;

	if (RB_INSERT(kroute_tree, &kt->krt, kr) != NULL)
		free(kr);	/* kernel route already there, no problem */

	/* special protection for loopback */
	if ((kr6 = calloc(1, sizeof(struct kroute6))) == NULL) {
		log_warn("%s", __func__);
		return (-1);
	}
	memcpy(&kr6->prefix, &in6addr_loopback, sizeof(kr6->prefix));
	kr6->prefixlen = 128;
	kr6->flags = F_CONNECTED;

	if (RB_INSERT(kroute6_tree, &kt->krt6, kr6) != NULL)
		free(kr6);	/* kernel route already there, no problem */

	return (0);
}

u_int8_t
prefixlen_classful(in_addr_t ina)
{
	/* it hurt to write this. */

	if (ina >= 0xf0000000U)		/* class E */
		return (32);
	else if (ina >= 0xe0000000U)	/* class D */
		return (4);
	else if (ina >= 0xc0000000U)	/* class C */
		return (24);
	else if (ina >= 0x80000000U)	/* class B */
		return (16);
	else				/* class A */
		return (8);
}

u_int8_t
mask2prefixlen(in_addr_t ina)
{
	if (ina == 0)
		return (0);
	else
		return (33 - ffs(ntohl(ina)));
}

u_int8_t
mask2prefixlen6(struct sockaddr_in6 *sa_in6)
{
	u_int8_t	*ap, *ep;
	u_int		 l = 0;

	/*
	 * sin6_len is the size of the sockaddr so substract the offset of
	 * the possibly truncated sin6_addr struct.
	 */
	ap = (u_int8_t *)&sa_in6->sin6_addr;
	ep = (u_int8_t *)sa_in6 + sizeof (struct in6_addr);
	for (; ap < ep; ap++) {
		/* this "beauty" is adopted from sbin/route/show.c ... */
		switch (*ap) {
		case 0xff:
			l += 8;
			break;
		case 0xfe:
			l += 7;
			goto done;
		case 0xfc:
			l += 6;
			goto done;
		case 0xf8:
			l += 5;
			goto done;
		case 0xf0:
			l += 4;
			goto done;
		case 0xe0:
			l += 3;
			goto done;
		case 0xc0:
			l += 2;
			goto done;
		case 0x80:
			l += 1;
			goto done;
		case 0x00:
			goto done;
		default:
			fatalx("non contiguous inet6 netmask");
		}
	}

 done:
	if (l > sizeof(struct in6_addr) * 8)
		fatalx("%s: prefixlen %d out of bound", __func__, l);
	return (l);
}

static struct in6_addr *
prefixlen2mask6(u_int8_t prefixlen)
{
	static struct in6_addr	mask;
	int			i;

	bzero(&mask, sizeof(mask));
	for (i = 0; i < prefixlen / 8; i++)
		mask.s6_addr[i] = 0xff;
	i = prefixlen % 8;
	if (i)
		mask.s6_addr[prefixlen / 8] = 0xff00 >> i;

	return (&mask);
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/*
 * rtsock related functions
 */

static const char *
rtm_type_str(int action)
{
	switch (action) {
	case RTM_ADD: return ("RTM_ADD");
	case RTM_DELETE: return ("RTM_DELETE");
	case RTM_CHANGE: return ("RTM_CHANGE");
	case RTM_GET: return ("RTM_GET");
	case RTM_LOSING: return ("RTM_LOSING");
	case RTM_REDIRECT: return ("RTM_REDIRECT");
	case RTM_MISS: return ("RTM_MISS");
	case RTM_LOCK: return ("RTM_LOCK");
	case RTM_OLDADD: return ("RTM_OLDADD");
	case RTM_OLDDEL: return ("RTM_OLDDEL");
	case RTM_RESOLVE: return ("RTM_RESOLVE");
	case RTM_NEWADDR: return ("RTM_NEWADDR");
	case RTM_DELADDR: return ("RTM_DELADDR");
	case RTM_IFINFO: return ("RTM_IFINFO");
	case RTM_CHGADDR: return ("RTM_CHGADDR");
	case RTM_FREEADDR: return ("RTM_FREEADDR");
	default: return ("UNKNOWN");
	}
}

int
send_rtmsg(int fd, int action, struct ktable *kt, struct kroute *kroute)
{
	struct iovec		iov[8];
	struct rt_msghdr	hdr;
	struct sockaddr_in	prefix;
	struct sockaddr_in	nexthop;
	struct bgpd_addr	baddr;
	struct sockaddr_in	mask;
	struct sockaddr_dl	intf;
	int			iovcnt = 0;
	struct kroute	*gkr = kroute;

	if (!kt->fib_sync)
		return (0);

	/* initialize header */
	bzero(&hdr, sizeof(hdr));
	hdr.rtm_version = RTM_VERSION;

	if (action != RTM_DELETE)
		hdr.rtm_flags |= RTF_PROTO2;

	hdr.rtm_type = action;
	if (kroute->flags & F_BLACKHOLE)
		hdr.rtm_flags |= RTF_BLACKHOLE;
	if (kroute->flags & F_REJECT)
		hdr.rtm_flags |= RTF_REJECT;
	if (kroute->prefixlen == 32)
		hdr.rtm_flags |= RTF_HOST;
	hdr.rtm_seq = kr_state.rtseq++;	/* overflow doesn't matter */
	hdr.rtm_msglen = sizeof(hdr);
	/* adjust iovec */
	iov[iovcnt].iov_base = &hdr;
	iov[iovcnt++].iov_len = sizeof(hdr);

	bzero(&prefix, sizeof(prefix));
	prefix.sin_family = AF_INET;
	prefix.sin_addr.s_addr = kroute->prefix.s_addr;
	/* adjust header */
	hdr.rtm_addrs |= RTA_DST;
	hdr.rtm_msglen += sizeof(prefix);
	/* adjust iovec */
	iov[iovcnt].iov_base = &prefix;
	iov[iovcnt++].iov_len = sizeof(prefix);

	bzero(&nexthop, sizeof(nexthop));
	if (kroute->nexthop.s_addr != 0) {
		nexthop.sin_family = AF_INET;
		nexthop.sin_addr.s_addr = kroute->nexthop.s_addr;
		/* adjust header */
		hdr.rtm_flags |= RTF_GATEWAY;
		hdr.rtm_addrs |= RTA_GATEWAY;
		hdr.rtm_msglen += sizeof(nexthop);
		/* adjust iovec */
		iov[iovcnt].iov_base = &nexthop;
		iov[iovcnt++].iov_len = sizeof(nexthop);

		/*
		 * Workaround: illumos often needs interfaces tagged on routes
		 * explicitly (especially for routes via point-to-point links).
		 * Look for the route to the nexthop gateway and we'll use that
		 * to add the RTA_IFP further down.
		 */
		baddr = (struct bgpd_addr){ .v4 = kroute->nexthop };
		gkr = kroute_match(kt, &baddr, 1);
	}

	bzero(&mask, sizeof(mask));
	mask.sin_family = AF_INET;
	mask.sin_addr.s_addr = htonl(prefixlen2mask(kroute->prefixlen));
	/* adjust header */
	hdr.rtm_addrs |= RTA_NETMASK;
	hdr.rtm_msglen += sizeof(mask);
	/* adjust iovec */
	iov[iovcnt].iov_base = &mask;
	iov[iovcnt++].iov_len = sizeof(mask);

	/*
	 * If we know what interface this route will have to go out, always
	 * tag the route. The kernel makes a best-effort attempt to add these
	 * tags for us when it needs them, but it's pretty shocking at it.
	 *
	 * Without doing this, routes via point-to-point links end up not
	 * being tagged (and thus not able to route actual traffic) almost
	 * 50% of the time.
	 */
	if (gkr != NULL && gkr->kif != NULL) {
		bzero(&intf, sizeof (intf));
		intf.sdl_family = AF_LINK;
		intf.sdl_index = gkr->kif->ifindex;
		intf.sdl_nlen = strlen(gkr->kif->ifname);
		strlcpy(intf.sdl_data, gkr->kif->ifname,
		    sizeof (intf.sdl_data));
		/* adjust header */
		hdr.rtm_addrs |= RTA_IFP;
		hdr.rtm_msglen += sizeof(intf);
		/* adjust iovec */
		iov[iovcnt].iov_base = &intf;
		iov[iovcnt++].iov_len = sizeof(intf);
	}

	char *prefstr = strdup(inet_ntoa(kroute->prefix));
	char *gwstr = strdup(nexthop.sin_family == AF_INET ?
	    inet_ntoa(nexthop.sin_addr) : "none");
	log_warnx("%s: action %s, prefix %s/%u, gw %s, flags = %x, addrs = %x",
	    __func__, rtm_type_str(hdr.rtm_type), prefstr, kroute->prefixlen,
	    gwstr, hdr.rtm_flags, hdr.rtm_addrs);
	free(prefstr);
	free(gwstr);

	if (writev(fd, iov, iovcnt) == -1) {
		if (errno == ESRCH) {
			if (hdr.rtm_type == RTM_DELETE) {
				/*
				 * On illumos, this often happens if a route
				 * was tagged for an interface which has just
				 * gone down. The route disappears from the
				 * table without any notification, and if the
				 * interface comes back up later it will also
				 * silently reappear.
				 *
				 * There's no way to see, change or delete a
				 * ghost route while the interface is down.
				 *
				 * Once the interface is back up we will
				 * (hopefully) detect the ghosts' reappearance
				 * by doing a full sync of the routing table
				 * from mib2 and we will delete it then.
				 */
				log_warnx("route to %s/%u vanished before "
				    "delete, might become a ghost",
				    inet_ntoa(kroute->prefix),
				    kroute->prefixlen);
				return (0);
			}
		}
		log_warn("%s: action %s, prefix %s/%u", __func__,
		    rtm_type_str(hdr.rtm_type), inet_ntoa(kroute->prefix),
		    kroute->prefixlen);
		(void) fetchtable(kt, 0);
		return (0);
	}

	return (0);
}

int
send_rt6msg(int fd, int action, struct ktable *kt, struct kroute6 *kroute)
{
	struct iovec		iov[7];
	struct rt_msghdr	hdr;
	struct pad {
		struct sockaddr_in6	addr;
		char			pad[sizeof(long)];
	} prefix, nexthop, mask;
	int			iovcnt = 0;

	if (!kt->fib_sync)
		return (0);

	/* initialize header */
	bzero(&hdr, sizeof(hdr));
	hdr.rtm_version = RTM_VERSION;

	hdr.rtm_flags |= RTF_PROTO2;

	hdr.rtm_type = action;
	if (kroute->flags & F_BLACKHOLE)
		hdr.rtm_flags |= RTF_BLACKHOLE;
	if (kroute->flags & F_REJECT)
		hdr.rtm_flags |= RTF_REJECT;
	if (kroute->prefixlen == 128)
		hdr.rtm_flags |= RTF_HOST;
	hdr.rtm_seq = kr_state.rtseq++;	/* overflow doesn't matter */
	hdr.rtm_msglen = sizeof(hdr);
	/* adjust iovec */
	iov[iovcnt].iov_base = &hdr;
	iov[iovcnt++].iov_len = sizeof(hdr);

	bzero(&prefix, sizeof(prefix));
	prefix.addr.sin6_family = AF_INET6;
	memcpy(&prefix.addr.sin6_addr, &kroute->prefix,
	    sizeof(struct in6_addr));
	/* XXX scope does not matter or? */
	/* adjust header */
	hdr.rtm_addrs |= RTA_DST;
	hdr.rtm_msglen += ROUNDUP(sizeof(struct sockaddr_in6));
	/* adjust iovec */
	iov[iovcnt].iov_base = &prefix;
	iov[iovcnt++].iov_len = ROUNDUP(sizeof(struct sockaddr_in6));

	if (memcmp(&kroute->nexthop, &in6addr_any, sizeof(struct in6_addr))) {
		bzero(&nexthop, sizeof(nexthop));
		nexthop.addr.sin6_family = AF_INET6;
		memcpy(&nexthop.addr.sin6_addr, &kroute->nexthop,
		    sizeof(struct in6_addr));
		/* adjust header */
		hdr.rtm_flags |= RTF_GATEWAY;
		hdr.rtm_addrs |= RTA_GATEWAY;
		hdr.rtm_msglen += ROUNDUP(sizeof(struct sockaddr_in6));
		/* adjust iovec */
		iov[iovcnt].iov_base = &nexthop;
		iov[iovcnt++].iov_len = ROUNDUP(sizeof(struct sockaddr_in6));
	}

	bzero(&mask, sizeof(mask));
	mask.addr.sin6_family = AF_INET6;
	memcpy(&mask.addr.sin6_addr, prefixlen2mask6(kroute->prefixlen),
	    sizeof(struct in6_addr));
	/* adjust header */
	hdr.rtm_addrs |= RTA_NETMASK;
	hdr.rtm_msglen += ROUNDUP(sizeof(struct sockaddr_in6));
	/* adjust iovec */
	iov[iovcnt].iov_base = &mask;
	iov[iovcnt++].iov_len = ROUNDUP(sizeof(struct sockaddr_in6));

retry:
	if (writev(fd, iov, iovcnt) == -1) {
		if (errno == ESRCH) {
			if (hdr.rtm_type == RTM_CHANGE) {
				hdr.rtm_type = RTM_ADD;
				goto retry;
			} else if (hdr.rtm_type == RTM_DELETE) {
				log_info("route %s/%u vanished before delete",
				    log_in6addr(&kroute->prefix),
				    kroute->prefixlen);
				return (0);
			}
		}
		log_warn("%s: action %u, prefix %s/%u", __func__, hdr.rtm_type,
		    log_in6addr(&kroute->prefix), kroute->prefixlen);
		(void) fetchtable(kt, 0);
		return (0);
	}

	return (0);
}

/* If octetstr() changes make an appropriate change to STR_EXPAND */
static char *
octetstr(const Octet_t *op, int code, char *dst, uint_t dstlen)
{
	int	i;
	char	*cp;

	cp = dst;
	if (op) {
		for (i = 0; i < op->o_length; i++) {
			switch (code) {
			case 'd':
				if (cp - dst + 4 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				(void) snprintf(cp, 5, "%d.",
				    0xff & op->o_bytes[i]);
				cp = strchr(cp, '\0');
				break;
			case 'a':
				if (cp - dst + 1 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				*cp++ = op->o_bytes[i];
				break;
			case 'h':
			default:
				if (cp - dst + 3 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				(void) snprintf(cp, 4, "%02x:",
				    0xff & op->o_bytes[i]);
				cp += 3;
				break;
			}
		}
	}
	if (code != 'a' && cp != dst)
		cp--;
	*cp = '\0';
	return (dst);
}

int
fetchifs(int ifindex)
{
	int		sock;
	int		rc;
	struct lifconf	lifc;
	struct lifnum	lifn;
	struct lifreq	lifr, *lifrp;
	size_t		i, n_ifs;
	uint64_t	flags, index;
	struct kif	*kif = NULL;
	int		found;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	bzero(&lifn, sizeof (lifn));
	lifn.lifn_family = AF_INET;
	lifn.lifn_flags = LIFC_ALLZONES | LIFC_UNDER_IPMP;
	if (ioctl(sock, SIOCGLIFNUM, &lifn) == -1) {
		n_ifs = 10;
	} else {
		n_ifs = lifn.lifn_count + 10;
	}

	bzero(&lifc, sizeof (lifc));
	lifc.lifc_family = AF_INET;
	lifc.lifc_flags = lifn.lifn_flags;
	lifc.lifc_len = n_ifs * sizeof (struct lifreq);
	lifc.lifc_buf = malloc(lifc.lifc_len);
	if (lifc.lifc_buf == NULL) {
		log_warn("%s", __func__);
		rc = -1;
		goto done;
	}

	if (ioctl(sock, SIOCGLIFCONF, &lifc) == -1) {
		log_warn("%s: SIOCGLIFCONF", __func__);
		rc = -1;
		goto done;
	}

	n_ifs = lifc.lifc_len / sizeof (struct lifreq);

	for (i = 0; i < n_ifs; ++i) {
		lifrp = &lifc.lifc_req[i];

		bzero(&lifr, sizeof (lifr));
		strlcpy(lifr.lifr_name, lifrp->lifr_name, LIFNAMSIZ);
		if (ioctl(sock, SIOCGLIFFLAGS, &lifr) == -1) {
			log_warn("%s: SIOCGLIFFLAGS", __func__);
			/* Interface disappeared while we weren't looking */
			if (errno == ENXIO)
				continue;
			rc = -1;
			goto done;
		}
		flags = lifr.lifr_flags;

		bzero(&lifr, sizeof (lifr));
		strlcpy(lifr.lifr_name, lifrp->lifr_name, LIFNAMSIZ);
		if (ioctl(sock, SIOCGLIFINDEX, &lifr) == -1) {
			log_warn("%s: SIOCGLIFINDEX", __func__);
			/* Interface disappeared while we weren't looking */
			if (errno == ENXIO)
				continue;
			rc = -1;
			goto done;
		}
		index = lifr.lifr_index;

		kif = kif_find(index);
		if (kif == NULL) {
			kif = calloc(1, sizeof (struct kif));
			if (kif == NULL) {
				log_warn("%s", __func__);
				rc = -1;
				goto done;
			}
			found = 0;
		} else {
			found = 1;
		}

		kif->ifindex = index;
		strlcpy(kif->ifname, lifrp->lifr_name, sizeof (kif->ifname));
		kif->flags = flags;
		kif->rdomain = 0;
		kif->link_state = LINK_STATE_DOWN;
		if ((flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING))
			kif->link_state = LINK_STATE_UP;
		kif->if_type = lifrp->lifr_type;
		kif->nh_reachable = kif_validate(kif);
		kif->depend_state = kif_depend_state(kif);

		if (!found)
			kif_insert(kif);
		kif = NULL;
	}

	rc = 0;

done:
	free(kif);
	free(lifc.lifc_buf);
	close(sock);
	return (rc);
}

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			size_t salen;
			rti_info[i] = sa;

			switch (sa->sa_family) {
			case AF_UNSPEC:
			case AF_INET:
				salen = sizeof (struct sockaddr_in);
				break;
			case AF_INET6:
				salen = sizeof (struct sockaddr_in6);
				break;
			case AF_LINK:
				salen = sizeof (struct sockaddr_dl);
				break;
			default:
				rti_info[i] = NULL;
				continue;
			}
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(salen));
		} else {
			rti_info[i] = NULL;
		}
	}
}

int
dispatch_rtmsg(void)
{
	char			 buf[RT_BUF_SIZE];
	ssize_t			 n;
	char			*next, *lim;
	struct rt_msghdr	*rtm;
	struct if_msghdr	*ifm;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	struct ktable		*kt;

	if ((n = read(kr_state.fd, &buf, sizeof(buf))) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return (0);
		log_warn("%s: read error", __func__);
		return (-1);
	}

	if (n == 0) {
		log_warnx("routing socket closed");
		return (-1);
	}

	lim = buf + n;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (lim < next + sizeof(u_short) ||
		    lim < next + rtm->rtm_msglen)
			fatalx("%s: partial rtm in buffer", __func__);
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		switch (rtm->rtm_type) {
		case RTM_ADD:
		case RTM_CHANGE:
		case RTM_DELETE:
			sa = (struct sockaddr *)(next + sizeof (struct rt_msghdr));
			get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
			if (rtm->rtm_pid == kr_state.pid) /* cause by us */
				continue;
			if (rtm->rtm_errno)		 /* failed attempts */
				continue;
			if (rtm->rtm_flags & RTF_LLINFO) /* arp cache */
				continue;
			if ((kt = ktable_get(0)) == NULL)
				continue;
			if (dispatch_rtmsg_addr(rtm, rti_info, kt) == -1)
				return (-1);
			break;
		case RTM_IFINFO:
			ifm = (struct if_msghdr *)rtm;
			if ((kt = ktable_get(0)) == NULL)
				continue;
			if (dispatch_rtmsg_if(ifm, kt) == -1)
				return (-1);
			break;
		default:
			/* ignore for now */
			break;
		}
	}
	return (0);
}

int
dispatch_rtmsg_if(const struct if_msghdr *ifm, struct ktable *kt)
{
	struct kif		*kif;
	int			 sock;
	int			 rc;
	struct lifreq		 lifr;
	struct kif_kr		*kkr;
	struct kif_kr6		*kkr6;
	uint8_t			 reachable;

	kif = kif_find(ifm->ifm_index);
	if (kif == NULL)
		return (fetchifs(0));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}

	bzero(&lifr, sizeof (lifr));
	strlcpy(lifr.lifr_name, kif->ifname, sizeof (lifr.lifr_name));

	if (ioctl(sock, SIOCGLIFFLAGS, &lifr) == -1) {
		if (errno == ENXIO) {
			kif_remove(kif);
			rc = 0;
			goto done;
		}
		log_warn("%s: SIOCGLIFFLAGS", __func__);
		rc = -1;
		goto done;
	}

	kif->flags = lifr.lifr_flags;
	kif->link_state = LINK_STATE_DOWN;
	if ((kif->flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING))
		kif->link_state = LINK_STATE_UP;

	kif->depend_state = kif_depend_state(kif);
	kr_send_dependon(kif);

	reachable = kif_validate(kif);
	if (reachable == kif->nh_reachable) {
		/*
		 * Reachability hasn't changed: we shouldn't need to update
		 * nexthops or re-sync the FIB.
		 */
		rc = 0;
		goto done;
	}
	kif->nh_reachable = reachable;

	log_info("%s: if status change on %s", __func__, kif->ifname);

	/*
	 * Force a full routing table refresh: see the comment about ghost
	 * routes in send_rtmsg().
	 *
	 * We want to do this before we update nexthop state, because that
	 * might cause us to add/remove routes.
	 *
	 * This doesn't always work, because the ghosts are racey. :(
	 */
	(void)fetchtable(kt, 0);

	LIST_FOREACH(kkr, &kif->kroute_l, entry) {
		knexthop_track(kt, kkr->kr->ifindex);
	}
	LIST_FOREACH(kkr6, &kif->kroute6_l, entry) {
		knexthop_track(kt, kkr6->kr->ifindex);
	}

	rc = 0;

done:
	close(sock);
	return (rc);
}

int
dispatch_rtmsg_addr(struct rt_msghdr *rtm, struct sockaddr *rti_info[RTAX_MAX],
    struct ktable *kt)
{
	struct sockaddr		*sa;
	struct sockaddr_in	*sa_in;
	struct sockaddr_in6	*sa_in6;
	struct kroute	*kr;
	struct kroute6	*kr6;
	struct bgpd_addr	 prefix;
	int			 flags, oflags, mpath = 0, changed = 0;
	u_int16_t		 ifindex;
	u_int8_t		 prefixlen;
	u_int8_t		 prio;

	flags = 0;
	ifindex = 0;
	prefixlen = 0;
	bzero(&prefix, sizeof(prefix));

	if ((sa = rti_info[RTAX_DST]) == NULL) {
		log_warnx("empty route message");
		return (0);
	}

	if (rtm->rtm_flags & RTF_STATIC)
		flags |= F_STATIC;
	if (rtm->rtm_flags & RTF_BLACKHOLE)
		flags |= F_BLACKHOLE;
	if (rtm->rtm_flags & RTF_REJECT)
		flags |= F_REJECT;
#ifdef RTF_MPATH
	if (rtm->rtm_flags & RTF_MPATH)
		mpath = 1;
#endif

	prio = 0;
	if (rtm->rtm_flags & RTF_PROTO2)
		prio = RTP_BGP;

	switch (sa->sa_family) {
	case AF_INET:
		prefix.aid = AID_INET;
		prefix.v4.s_addr = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
		sa_in = (struct sockaddr_in *)rti_info[RTAX_NETMASK];
		if (sa_in != NULL) {
			prefixlen = mask2prefixlen(sa_in->sin_addr.s_addr);
		} else if (rtm->rtm_flags & RTF_HOST)
			prefixlen = 32;
		else
			prefixlen =
			    prefixlen_classful(prefix.v4.s_addr);
		break;
	case AF_INET6:
		prefix.aid = AID_INET6;
		memcpy(&prefix.v6, &((struct sockaddr_in6 *)sa)->sin6_addr,
		    sizeof(struct in6_addr));
		sa_in6 = (struct sockaddr_in6 *)rti_info[RTAX_NETMASK];
		if (sa_in6 != NULL) {
			prefixlen = mask2prefixlen6(sa_in6);
		} else if (rtm->rtm_flags & RTF_HOST)
			prefixlen = 128;
		else
			fatalx("in6 net addr without netmask");
		break;
	default:
		return (0);
	}

	log_debug("%s: msg type %u (flags %x) about %s/%u",
	    __func__, rtm->rtm_type, rtm->rtm_flags, log_addr(&prefix),
	    prefixlen);

	if (flags == 0 && !(rtm->rtm_flags & RTF_GATEWAY)) {
		if ((sa = rti_info[RTAX_IFP]) != NULL) {
			struct sockaddr_dl	*sdl;
			flags |= F_CONNECTED;
			switch (sa->sa_family) {
			case AF_LINK:
				sdl = (struct sockaddr_dl *)sa;
				if (sdl->sdl_nlen >= sizeof (sdl->sdl_data))
					fatalx("link name too long");
				sdl->sdl_data[sdl->sdl_nlen] = 0;
				ifindex = if_nametoindex(sdl->sdl_data);
				break;
			default:
				fatalx("non-gateway route without ifp");
			}
			sa = NULL;
			mpath = 0;
		} else {
			/*
			 * We don't have enough info on this, let's go ask
			 * mib2 about it.
			 */
			return (fetchtable(kt, 0));
		}
	}

	if (rtm->rtm_type == RTM_DELETE) {
		switch (prefix.aid) {
		case AID_INET:
			sa_in = (struct sockaddr_in *)sa;
			if ((kr = kroute_find(kt, prefix.v4, prefixlen,
			    prio)) == NULL)
				return (0);

			if (mpath)
				/* get the correct route */
				if ((kr = kroute_matchgw(kr, sa_in)) == NULL) {
					log_warnx("%s[delete]: "
					    "mpath route not found", __func__);
					return (0);
				}

			if (kr->flags & F_BGPD) {
				kr->flags &= ~F_BGPD_INSERTED;
				return (0);
			}

			if (kroute_remove(kt, kr) == -1)
				return (-1);
			break;
		case AID_INET6:
			sa_in6 = (struct sockaddr_in6 *)sa;
			if ((kr6 = kroute6_find(kt, &prefix.v6, prefixlen,
			    prio)) == NULL)
				return (0);

			if (mpath)
				/* get the correct route */
				if ((kr6 = kroute6_matchgw(kr6, sa_in6)) ==
				    NULL) {
					log_warnx("%s[delete]: IPv6 mpath "
					    "route not found", __func__);
					return (0);
				}

			if (kr6->flags & F_BGPD) {
				kr6->flags &= ~F_BGPD_INSERTED;
				return (0);
			}

			if (kroute6_remove(kt, kr6) == -1)
				return (-1);
			break;
		}
		return (0);
	}

	if (sa == NULL && !(flags & F_CONNECTED)) {
		log_warnx("%s: no nexthop for %s/%u",
		    __func__, log_addr(&prefix), prefixlen);
		return (0);
	}

	switch (prefix.aid) {
	case AID_INET:
		sa_in = (struct sockaddr_in *)sa;
		if ((kr = kroute_find(kt, prefix.v4, prefixlen, prio)) != NULL) {
			if (!(kr->flags & F_BGPD)) {
				/* get the correct route */
				if (mpath && rtm->rtm_type == RTM_CHANGE &&
				    (kr = kroute_matchgw(kr, sa_in)) == NULL) {
					log_warnx("%s[change]: "
					    "mpath route not found", __func__);
					goto add4;
				} else if (mpath && rtm->rtm_type == RTM_ADD)
					goto add4;

				if (sa_in != NULL) {
					if (kr->nexthop.s_addr !=
					    sa_in->sin_addr.s_addr)
						changed = 1;
					kr->nexthop.s_addr =
					    sa_in->sin_addr.s_addr;
				} else {
					if (kr->nexthop.s_addr != 0)
						changed = 1;
					kr->nexthop.s_addr = 0;
				}

				if (kr->flags & F_NEXTHOP)
					flags |= F_NEXTHOP;

				oflags = kr->flags;
				if (flags != oflags)
					changed = 1;
				kr->flags = flags;

				if ((oflags & F_CONNECTED) &&
				    !(flags & F_CONNECTED)) {
					kif_kr_remove(kr);
					kr_redistribute(IMSG_NETWORK_ADD,
					    kt, kr);
				}
				if ((flags & F_CONNECTED) &&
				    !(oflags & F_CONNECTED)) {
					kif_kr_insert(kr);
					kr_redistribute(IMSG_NETWORK_ADD,
					    kt, kr);
				}
				if (kr->flags & F_NEXTHOP && changed)
					knexthop_track(kt, kr->ifindex);
			} else {
				kr->flags &= ~F_BGPD_INSERTED;
			}
		} else if (rtm->rtm_type == RTM_CHANGE) {
			log_warnx("%s: change req for %s/%u: not in table",
			    __func__, log_addr(&prefix), prefixlen);
			return (0);
		} else {
add4:
			if ((kr = calloc(1,
			    sizeof(struct kroute))) == NULL) {
				log_warn("%s", __func__);
				return (-1);
			}
			kr->prefix.s_addr = prefix.v4.s_addr;
			kr->prefixlen = prefixlen;
			if (sa_in != NULL)
				kr->nexthop.s_addr = sa_in->sin_addr.s_addr;
			else
				kr->nexthop.s_addr = 0;
			kr->flags = flags;
			kr->ifindex = ifindex;
			kr->priority = prio;

			kroute_insert(kt, kr);
		}
		break;
	case AID_INET6:
		sa_in6 = (struct sockaddr_in6 *)sa;
		if ((kr6 = kroute6_find(kt, &prefix.v6, prefixlen, prio)) !=
		    NULL) {
			if (!(kr6->flags & F_BGPD)) {
				/* get the correct route */
				if (mpath && rtm->rtm_type == RTM_CHANGE &&
				    (kr6 = kroute6_matchgw(kr6, sa_in6)) ==
				    NULL) {
					log_warnx("%s[change]: IPv6 mpath "
					    "route not found", __func__);
					goto add6;
				} else if (mpath && rtm->rtm_type == RTM_ADD)
					goto add6;

				if (sa_in6 != NULL) {
					if (memcmp(&kr6->nexthop,
					    &sa_in6->sin6_addr,
					    sizeof(struct in6_addr)))
						changed = 1;
					memcpy(&kr6->nexthop,
					    &sa_in6->sin6_addr,
					    sizeof(struct in6_addr));
				} else {
					if (memcmp(&kr6->nexthop,
					    &in6addr_any,
					    sizeof(struct in6_addr)))
						changed = 1;
					memcpy(&kr6->nexthop,
					    &in6addr_any,
					    sizeof(struct in6_addr));
				}

				if (kr6->flags & F_NEXTHOP)
					flags |= F_NEXTHOP;

				oflags = kr6->flags;
				if (flags != oflags)
					changed = 1;
				kr6->flags = flags;

				if ((oflags & F_CONNECTED) &&
				    !(flags & F_CONNECTED)) {
					kif_kr6_remove(kr6);
					kr_redistribute6(IMSG_NETWORK_ADD,
					    kt, kr6);
				}
				if ((flags & F_CONNECTED) &&
				    !(oflags & F_CONNECTED)) {
					kif_kr6_insert(kr6);
					kr_redistribute6(IMSG_NETWORK_ADD,
					    kt, kr6);
				}

				if (kr6->flags & F_NEXTHOP && changed)
					knexthop_track(kt, kr6->ifindex);
			} else {
				kr6->flags &= ~F_BGPD_INSERTED;
			}
		} else if (rtm->rtm_type == RTM_CHANGE) {
			log_warnx("%s: change req for %s/%u: not in table",
			    __func__, log_addr(&prefix), prefixlen);
			return (0);
		} else {
add6:
			if ((kr6 = calloc(1,
			    sizeof(struct kroute6))) == NULL) {
				log_warn("%s", __func__);
				return (-1);
			}
			memcpy(&kr6->prefix, &prefix.v6,
			    sizeof(struct in6_addr));
			kr6->prefixlen = prefixlen;
			if (sa_in6 != NULL)
				memcpy(&kr6->nexthop, &sa_in6->sin6_addr,
				    sizeof(struct in6_addr));
			else
				memcpy(&kr6->nexthop, &in6addr_any,
				    sizeof(struct in6_addr));
			kr6->flags = flags;
			kr6->ifindex = ifindex;
			kr6->priority = prio;

			kroute6_insert(kt, kr6);
		}
		break;
	}

	return (0);
}
