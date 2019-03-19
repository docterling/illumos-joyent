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

#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
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
# include "netinet/ip_scan.h"
#endif
#ifdef IPFILTER_SYNC
# include "netinet/ip_sync.h"
#endif
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#ifdef IPFILTER_COMPILED
# include "netinet/ip_rules.h"
#endif
#if defined(_KERNEL)
#include <sys/sunddi.h>
#endif

#include "netinet/ipf_cfw.h"

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

/* XXX KEBE SAYS PUT A RING (buffer) ON IT! */

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
	cv_broadcast(&cfw_ringcv);
	mutex_exit(&cfw_ringlock);
}

/*
 * For now, merely copy one from the ring buffer into what's provided.
 * In the future, maybe lock-then-callback, even with a request for multiple
 * events?
 *
 * Also for now, if empty, cv_wait().
 */
void
ipf_cfwev_consume(cfwev_t *event)
{
	mutex_enter(&cfw_ringlock);

	/*
	 * Alternatives, use if and return B_FALSE or something instead
	 * of cv_wait()ing.
	 */
	while (cfw_ringstart == cfw_ringend && !cfw_ringfull)
		cv_wait(&cfw_ringcv, &cfw_ringlock);
	*event = cfw_evring[cfw_ringend];
	cfw_ringend++;
	cfw_ringend &= IPF_CFW_RING_MASK;
	cfw_ringfull = B_FALSE;
	mutex_exit(&cfw_ringlock);
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
	/*
	 * IPF code elsewhere does the cheesy single-flag check, even thogh
	 * there are two flags in a rule (one for in, one for out).
	 */
	event.cfwev_direction = (fr->fr_flags & FR_INQUE) ?
	    CFWDIR_IN : CFWDIR_OUT;

	event.cfwev_protocol = fin->fin_p;
	/* XXX KEBE SAYS ICMP stuff should fall in here too. */
	event.cfwev_sport = fin->fin_sport;
	event.cfwev_dport = fin->fin_dport;

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
	event.cfwev_direction = (is->is_rule->fr_flags & FR_INQUE) ?
	    CFWDIR_IN : CFWDIR_OUT;
	event.cfwev_protocol = is->is_p;
	switch (is->is_p) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
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
	event.cfwev_ruleid = is->is_rulen;
	memcpy(event.cfwev_ruleuuid, is->is_uuid, sizeof (uuid_t));

	ipf_cfwev_report(&event);
	/* DTRACE_PROBE1(ipf__cfw__state, cfwev_t *, &event); */
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
