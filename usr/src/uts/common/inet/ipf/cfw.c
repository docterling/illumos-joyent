/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* XXX KEBE ASKS --> Is this affected instead by the IPFILTER.LICENCE? */

/*
 * Copyright 2019, Joyent, Inc.
 */

/* IPF oddness for compilation in userland for IPF tests. */
#if defined(KERNEL) || defined(_KERNEL)
#undef KERNEL
#undef _KERNEL
#define	KERNEL	1
#define	_KERNEL	1
#endif

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include "netinet/ip_compat.h"
#ifdef	USE_INET6
#include <netinet/icmp6.h>
#endif
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_auth.h"
#include "netinet/ipf_stack.h"
#ifdef IPFILTER_SCAN
#include "netinet/ip_scan.h"
#endif
#ifdef IPFILTER_SYNC
#include "netinet/ip_sync.h"
#endif
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#ifdef IPFILTER_COMPILED
#include "netinet/ip_rules.h"
#endif
#if defined(_KERNEL)
#include <sys/sunddi.h>
#endif

#include "netinet/ipf_cfw.h"
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/ddi.h>

/*
 * cfw == Cloud Firewall ==> routines for a global-zone data collector about
 * ipf events for SmartOS.  The only ones that CFW cares about are ones
 * enforced by global-zone-controlled rulesets.
 *
 * The variable below is mdb-hackable to experiment with turning it on and
 * off. Eventually this will tie into a new ipf (GZ-only) device that flips
 * this on when there is an open instance.  It may also consume an fr_flag
 * to have per-rule granularity.
 */
boolean_t ipf_cfwlog_enabled;

/*
 * Because ipf's test tools in $SRC/cmd insert all of these files, we need to
 * stub out what we can vs. drag in even more headers and who knows what else.
 */
#ifdef _KERNEL

/*
 * CFW event ring buffer.  Remember, this is for ALL ZONES because only a
 * global-zone event-reader will be consuming these.  In other words, it's
 * not something to instantiate per-netstack.
 */

/*
 * We may want to get more sophisticated and performant (e.g. per-processor),
 * but for now keep the ring buffer simple and stupid.
 */

/* Must be a power of 2, to be bitmaskable, and must be countable by a uint_t */

#define	IPF_CFW_RING_BUFS	1024
#define	IPF_CFW_RING_MASK (IPF_CFW_RING_BUFS - 1)

/* Assume C's init-to-zero is sufficient for these types... */
static kmutex_t cfw_ringlock;
static kcondvar_t cfw_ringcv;

static cfwev_t cfw_evring[IPF_CFW_RING_BUFS];
/* If these are equal, we're either empty or full. */
static uint_t cfw_ringstart, cfw_ringend;
static boolean_t cfw_ringfull;	/* Tell the difference here! */
static uint64_t cfw_evreports;
static uint64_t cfw_evdrops;

/*
 * For now redundant-copy. In the future, MAYBE pass parms and do the copying
 * here?
 */
static void
ipf_cfwev_report(cfwev_t *event)
{
	mutex_enter(&cfw_ringlock);
	if (cfw_ringfull) {
		cfw_ringstart++;
		cfw_ringstart &= IPF_CFW_RING_MASK;
		cfw_ringend++;
		cfw_ringend &= IPF_CFW_RING_MASK;
		DTRACE_PROBE(ipf__cfw__evdrop);
		cfw_evdrops++;
		cfw_evring[cfw_ringend] = *event;
	} else {
		cfw_evring[cfw_ringend] = *event;
		cfw_ringend++;
		cfw_ringend &= IPF_CFW_RING_MASK;
		cfw_ringfull = (cfw_ringend == cfw_ringstart);
	}
	cfw_evreports++;
	cv_broadcast(&cfw_ringcv);
	mutex_exit(&cfw_ringlock);
}

/*
 * For now, merely copy one from the ring buffer into what's provided.
 * In the future, maybe lock-then-callback, even with a request for multiple
 * events?
 *
 * Also for now, if empty, either cv_wait() or return B_FALSE, depending on
 * "block".
 */
boolean_t
ipf_cfwev_consume(cfwev_t *event, boolean_t block)
{
	mutex_enter(&cfw_ringlock);

	/*
	 * Return B_FALSE if non-block and no data, OR if we receive a signal.
	 */
	while ((cfw_ringstart == cfw_ringend) && !cfw_ringfull) {
		if (!block || !cv_wait_sig(&cfw_ringcv, &cfw_ringlock)) {
			mutex_exit(&cfw_ringlock);
			return (B_FALSE);
		}
	}

	*event = cfw_evring[cfw_ringstart];
	cfw_ringstart++;
	cfw_ringstart &= IPF_CFW_RING_MASK;
	cfw_ringfull = B_FALSE;
	mutex_exit(&cfw_ringlock);
	return (B_TRUE);
}

/*
 * More sophisticated access to multiple CFW events that can allow copying
 * straight from the ring buffer up to userland.  Requires a callback (which
 * could call uiomove() directly, OR to a local still-in-kernel buffer) that
 * must do the data copying-out.
 *
 * Callback function is of the form:
 *
 *	uint_t cfw_many_cb(cfwev_t *evptr, int num_avail, void *cbarg);
 *
 * The function must return how many events got consumed, which MUST be <= the
 * number available.  The function must ALSO UNDERSTAND that cfw_ringlock is
 * held during this time.  The function may be called more than once, if the
 * available buffers wrap-around OR "block" is set and we don't have enough
 * buffers.  If any callback returns 0, exit the function with however many
 * were consumed.
 *
 * This function, like the callback, returns the number of events *CONSUMED*.
 */

/*
 * If you wish to attempt to coalesce reads (to reduce the likelihood of one
 * event at a time during high load) change the number of tries below to
 * something not 0. Early experiments set this to 10.
 *
 * The wait between tries is in usecs in cfw_timeout_wait. The pessimal
 * case for this is a timeout_wait trickle of one event at a time.
 */
int cfw_timeout_tries = 0;
int cfw_timeout_wait = 10000;	/* 10ms wait. */

uint_t
ipf_cfwev_consume_many(uint_t num_requested, boolean_t block,
    cfwmanycb_t cfw_many_cb, void *cbarg)
{
	uint_t consumed = 0, cb_consumed, contig_size;
	int timeout_tries = cfw_timeout_tries;

	mutex_enter(&cfw_ringlock);
	/*
	 * Can goto here (ewww) if caller wants blocking. NOTE that
	 * num_requested may have been decremented and consumed may have been
	 * incremented if we arrive here via a goto after a cv_wait.
	 */

	/* Silly reality checks */
	ASSERT3U(cfw_ringstart, <, IPF_CFW_RING_BUFS);
	ASSERT3U(cfw_ringend, <, IPF_CFW_RING_BUFS);

from_the_top:
	if (cfw_ringstart > cfw_ringend || cfw_ringfull)
		contig_size = IPF_CFW_RING_BUFS - cfw_ringstart;
	else if (cfw_ringstart < cfw_ringend)
		contig_size = cfw_ringend - cfw_ringstart;
	else if (block && cv_wait_sig(&cfw_ringcv, &cfw_ringlock)) {
		/* Maybe something to consume now, try again. */
		goto from_the_top;
	} else {
		/* Nothing (more) to consume, return! */
		goto bail;
	}

	ASSERT(contig_size + cfw_ringstart == cfw_ringend ||
	    contig_size + cfw_ringstart == IPF_CFW_RING_BUFS);

	if (num_requested < contig_size)
		contig_size = num_requested;

	cb_consumed = cfw_many_cb(&(cfw_evring[cfw_ringstart]), contig_size,
	    cbarg);
	ASSERT(cb_consumed <= contig_size);
	cfw_ringstart += cb_consumed;
	consumed += cb_consumed;
	cfw_ringfull = (cfw_ringfull && cb_consumed == 0);
	if (cb_consumed < contig_size) {
		/* Caller clearly had a problem. Reality check and bail. */
		ASSERT((cfw_ringstart & IPF_CFW_RING_MASK) == cfw_ringstart);
		goto bail;
	}
	ASSERT(cb_consumed == contig_size);
	cfw_ringstart &= IPF_CFW_RING_MASK;	/* In case of wraparound. */
	num_requested -= contig_size;

	if (num_requested > 0 && cfw_ringstart != cfw_ringend) {
		/* We must have wrapped around the end of the buffer! */
		ASSERT(cfw_ringstart == 0);
		ASSERT(!cfw_ringfull);
		contig_size = cfw_ringend;
		if (num_requested < contig_size)
			contig_size = num_requested;
		cb_consumed = cfw_many_cb(&(cfw_evring[cfw_ringstart]),
		    contig_size, cbarg);
		cfw_ringstart += cb_consumed;
		consumed += cb_consumed;
		if (cb_consumed < contig_size) {
			/*
			 * Caller clearly had a problem. Reality check and
			 * bail.
			 */
			ASSERT(cfw_ringend > cfw_ringstart);
			goto bail;
		}
		ASSERT(cb_consumed == contig_size);
		num_requested -= contig_size;
	}

	ASSERT(consumed > 0);

	if (num_requested > 0 && block && timeout_tries > 0) {
		clock_t delta = drv_usectohz(cfw_timeout_wait);

		timeout_tries--;
		/* Nothing to consume, wait *a little bit* longer. */
		switch (cv_reltimedwait_sig(&cfw_ringcv, &cfw_ringlock, delta,
		    TR_CLOCK_TICK)) {
		case 0:
			/* Received signal! Throw out what we have. */
			DTRACE_PROBE1(ipf__cfw__sigdiscard, int, consumed);
			cfw_evdrops += consumed;
			consumed = 0;
			break;
		case -1:
			/* Time reached! Bail with what we got. */
			DTRACE_PROBE(ipf__cfw__timedexpired);
			break;
		default:
			/* Aha! We've got more! */
			DTRACE_PROBE(ipf__cfw__moredata);
			goto from_the_top;
		}
	}

bail:
	mutex_exit(&cfw_ringlock);
	return (consumed);
}

static inline zoneid_t
ifs_to_did(ipf_stack_t *ifs)
{
	if (ifs->ifs_zone_did == 0) {
		zone_t *zone;

		/*
		 * Because we can't get the zone_did at initialization time
		 * because most zone data isn't readily available then,
		 * cement the did in place now.
		 */
		ASSERT(ifs->ifs_zone != GLOBAL_ZONEID);
		zone = zone_find_by_id(ifs->ifs_zone);
		if (zone != NULL) {
			ifs->ifs_zone_did = zone->zone_did;
			zone_rele(zone);
		}
		/* Else we are either in shutdown or something weirder. */
	}
	return (ifs->ifs_zone_did);
}

/*
 * ipf_block_cfwlog()
 *
 * Called by fr_check().  Record drop events for a global-zone data collector.
 * Use rest-of-ipf-style names for the parameters.
 */
void
ipf_block_cfwlog(frentry_t *fr, fr_info_t *fin, ipf_stack_t *ifs)
{
	cfwev_t event = {0};

	/*
	 * We need a rule.
	 * Capture failure by using dtrace on this function's entry.
	 * 'ipf_block_cfwlog:entry /arg0 == NULL/ { printf("GOTCHA!\n"); }'
	 */
	if (fr == NULL)
		return;

	event.cfwev_type = CFWEV_BLOCK;
	event.cfwev_length = sizeof (event);
	/*
	 * IPF code elsewhere does the cheesy single-flag check, even thogh
	 * there are two flags in a rule (one for in, one for out).
	 */
	event.cfwev_direction = (fr->fr_flags & FR_INQUE) ?
	    CFWDIR_IN : CFWDIR_OUT;

	event.cfwev_protocol = fin->fin_p;
	/* NOTE: fin_*port is in host/native order. */
	/* XXX KEBE SAYS ICMP stuff should fall in here too. */
	event.cfwev_sport = htons(fin->fin_sport);
	event.cfwev_dport = htons(fin->fin_dport);

	if (fin->fin_v == IPV4_VERSION) {
		IN6_INADDR_TO_V4MAPPED(&fin->fin_src, &event.cfwev_saddr);
		IN6_INADDR_TO_V4MAPPED(&fin->fin_dst, &event.cfwev_daddr);
	} else {
		ASSERT3U(fin->fin_v, ==, IPV6_VERSION);
		event.cfwev_saddr = fin->fin_src6.in6;
		event.cfwev_daddr = fin->fin_dst6.in6;
	}

	/*
	 * XXX KEBE ASKS -> something better instead?!?
	 * uniqtime() is what ipf's GETKTIME() uses. It does give us tv_usec,
	 * but I'm not sure if it's suitable for what we need.
	 */
	uniqtime(&event.cfwev_tstamp);
	event.cfwev_zonedid = ifs_to_did(ifs);
	ASSERT(fin->fin_rule <= 0xffff);	/* Must fit in uint16_t... */
	event.cfwev_ruleid = fin->fin_rule;
	memcpy(event.cfwev_ruleuuid, fr->fr_uuid, sizeof (uuid_t));

	ipf_cfwev_report(&event);
	/* DTRACE_PROBE1(ipf__cfw__block, cfwev_t *, &event); */
}

/*
 * ipf_log_cfwlog()
 *
 * Twin of ipstate_log(), but records state events for a global-zone data
 * collector.
 */
void
ipf_log_cfwlog(struct ipstate *is, uint_t type, ipf_stack_t *ifs)
{
	cfwev_t event = {0};

	switch (type) {
	case ISL_NEW:
	case ISL_CLONE:
		event.cfwev_type = CFWEV_BEGIN;
		break;
	case ISL_EXPIRE:
	case ISL_FLUSH:
	case ISL_REMOVE:
	case ISL_KILLED:
	case ISL_ORPHAN:
#if 0
		event.cfwev_type = CFWEV_END;
		break;
#else
		/* We don't care about disappearances in CFW logging for now. */
		return;
#endif
	default:
		event.cfwev_type = CFWEV_BLOCK;
		break;
	}

	/*
	 * IPF code elsewhere does the cheesy single-flag check, even thogh
	 * there are two flags in a rule (one for in, one for out).
	 */
	event.cfwev_length = sizeof (event);
	event.cfwev_direction = (is->is_rule->fr_flags & FR_INQUE) ?
	    CFWDIR_IN : CFWDIR_OUT;
	event.cfwev_protocol = is->is_p;
	switch (is->is_p) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* NOTE: is_*port is in network order. */
		event.cfwev_sport = is->is_sport;
		event.cfwev_dport = is->is_dport;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		/* Scribble the ICMP type in sport... */
		event.cfwev_sport = is->is_icmp.ici_type;
		break;
	}

	if (is->is_v == IPV4_VERSION) {
		IN6_INADDR_TO_V4MAPPED(&is->is_src.in4, &event.cfwev_saddr);
		IN6_INADDR_TO_V4MAPPED(&is->is_dst.in4, &event.cfwev_daddr);
	} else {
		ASSERT3U(is->is_v, ==, IPV6_VERSION);
		event.cfwev_saddr = is->is_src.in6;
		event.cfwev_daddr = is->is_dst.in6;
	}

	/*
	 * XXX KEBE ASKS -> something better instead?!?
	 * uniqtime() is what ipf's GETKTIME() uses. It does give us tv_usec,
	 * but I'm not sure if it's suitable for what we need.
	 */
	uniqtime(&event.cfwev_tstamp);
	event.cfwev_zonedid = ifs_to_did(ifs);
	/* XXX KEBE ASKS -> good enough? */
	ASSERT(is->is_rulen <= 0xffff);	/* Must fit in uint16_t... */
	event.cfwev_ruleid = is->is_rulen;
	memcpy(event.cfwev_ruleuuid, is->is_uuid, sizeof (uuid_t));

	ipf_cfwev_report(&event);
	/* DTRACE_PROBE1(ipf__cfw__state, cfwev_t *, &event); */
}

typedef struct uio_error_s {
	struct uio *ue_uio;
	int ue_error;
} uio_error_t;

static uint_t
cfwlog_read_manycb(cfwev_t *evptr, uint_t num_avail, void *cbarg)
{
	uio_error_t *ue = (uio_error_t *)cbarg;

	ASSERT(MUTEX_HELD(&cfw_ringlock));

	/* XXX KEBE ASKS Should this be an ASSERT()? */
	if (ue->ue_error != 0)
		return (0);

	ue->ue_error = uiomove((caddr_t)evptr, num_avail * sizeof (*evptr),
	    UIO_READ, ue->ue_uio);
	/* 0 means error indication. */
	if (ue->ue_error)
		return (0);

	return (num_avail);
}

/* ARGSUSED */
int
ipf_cfwlog_read(dev_t dev, struct uio *uio, cred_t *cp)
{
	uint_t requested, consumed;
	uio_error_t ue = {uio, 0};
	boolean_t block;

	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_resid < sizeof (cfwev_t))
		return (EINVAL);
	/* XXX KEBE ASKS: Check for resid being too big?!? */

	block = ((uio->uio_fmode & (FNDELAY | FNONBLOCK)) == 0);
	requested = uio->uio_resid / sizeof (cfwev_t);
	ASSERT(requested > 0);

	/*
	 * As stated earlier, ipf_cfwev_consume_many() takes a callback.
	 * The callback may be called multiple times before we return.
	 * The callback will execute uiomove().
	 */
	consumed = ipf_cfwev_consume_many(requested, block, cfwlog_read_manycb,
	    &ue);
	ASSERT3U(consumed, <=, requested);
	if (!block && consumed == 0 && ue.ue_error == 0) {
		/* No data available. */
		ue.ue_error = EWOULDBLOCK;
	} else if (ue.ue_error != 0 || (block && consumed == 0)) {
		/* We had a problem... */
		if (ue.ue_error == 0) {
			/* Cover cv_wait_sig() receiving a signal. */
			ue.ue_error = EINTR;
		}
		mutex_enter(&cfw_ringlock);
		DTRACE_PROBE1(ipf__cfw__uiodiscard, int, consumed);
		cfw_evdrops += consumed;
		mutex_exit(&cfw_ringlock);
	}
	return (ue.ue_error);
}

#else
/* Blank stubs to satisfy userland's test stuff. */

void
ipf_log_cfwlog(struct ipstate *a, uint_t b, ipf_stack_t *c)
{
}

void
ipf_block_cfwlog(frentry_t *a, fr_info_t *b, ipf_stack_t *c)
{
}

#endif	/* _KERNEL */
