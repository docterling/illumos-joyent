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
#if defined(__NetBSD__)
# if (NetBSD >= 199905) && !defined(IPFILTER_LKM) && defined(_KERNEL)
#  include "opt_ipfilter_log.h"
# endif
#endif
#if defined(_KERNEL) && defined(__FreeBSD_version) && \
    (__FreeBSD_version >= 220000)
# if (__FreeBSD_version >= 400000)
#  if !defined(IPFILTER_LKM)
#   include "opt_inet6.h"
#  endif
#  if (__FreeBSD_version == 400019)
#   define CSUM_DELAY_DATA
#  endif
# endif
# include <sys/filio.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(_AIX51)
# include <sys/fcntl.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
# include <sys/file.h>
#else
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <stddef.h>
# include <sys/file.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#if !defined(__SVR4) && !defined(__svr4__) && !defined(__hpux) && \
    !defined(linux)
# include <sys/mbuf.h>
#else
# if !defined(linux)
#  include <sys/byteorder.h>
# endif
# if (SOLARIS2 < 5) && defined(sun)
#  include <sys/dditypes.h>
# endif
#endif
#ifdef __hpux
# define _NET_ROUTE_INCLUDED
#endif
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#if !defined(_KERNEL) && defined(__FreeBSD__)
# include "radix_ipf.h"
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#if defined(__sgi) && defined(IFF_DRVRLOCK) /* IRIX 6 */
# include <sys/hashing.h>
# include <netinet/in_var.h>
#endif
#include <netinet/tcp.h>
#if (!defined(__sgi) && !defined(AIX)) || defined(_KERNEL)
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
#endif
#ifdef __hpux
# undef _NET_ROUTE_INCLUDED
#endif
#include "netinet/ip_compat.h"
#ifdef	USE_INET6
# include <netinet/icmp6.h>
# if !defined(SOLARIS) && defined(_KERNEL) && !defined(__osf__) && \
	!defined(__hpux)
#  include <netinet6/in6_var.h>
# endif
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
#if defined(IPFILTER_BPF) && defined(_KERNEL)
# include <net/bpf.h>
#endif
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include "opt_ipfilter.h"
# endif
#endif
#include "netinet/ipl.h"
#if defined(_KERNEL)
#include <sys/sunddi.h>
#endif
/* END OF INCLUDES */

/* Extra includes outside normal ipf things. */
#include <sys/types.h>
#include <inet/ip6.h>
/* Because ipf compiles this kernel file in userland testing... */
#ifndef ASSERT3U
#define	ASSERT3U(a, b, c) ASSERT(a ## b ## c);
#endif	/* ASSERT3U */

/*
 * zstate == zone-state ==> routines for a global-zone data collector about
 * ipf events.
 *
 * XXX KEBE SAYS There are currently two approaches concurrently being
 * implemented:
 *
 * USE-STATE - Inserting collectors into the existing ipfilter "keep state"
 * routines.
 *
 * USE-CALL - Inserting collectors into "call actions" which are wrappers
 * around block or drop. Upside is not requiring the full weight of the
 * ipfilter state collection. Downside is it is possible we will be
 * reinventing enough to question why this approach existed in the first
 * place.
 *
 * Some of this file is USE-STATE exclusive, some is USE-CALL exclusive, some
 * is applicable to both.  Portions of this file will be labelled with
 * USE-CALL or USE-STATE as appropriate.
 *
 * The variable below is mdb-hackable to experiment with the different
 * approaches. mdb-induced value changes MUST be followed by reboots of zones
 * affected.
 */
ipf_zstate_enabled_t ipf_zstate_enabled;

/*
 * XXX KEBE ASKS MOVE THIS TO A HEADER FILE?
 */
#define	CFWEV_BLOCK	1
#define	CFWEV_BEGIN	2
#define	CFWEV_END	3
#define	CFWDIR_IN	1
#define	CFWDIR_OUT	2
typedef struct cfwev_s {
	uint16_t cfwev_type;	/* BEGIN, END, BLOCK */
	uint8_t cfwev_direction;
	uint8_t cfwev_protocol;	/* IPPROTO_* */
	/*
	 * The above "direction" informs if src/dst are local/remote or
	 * remote/local.
	 */
	uint16_t cfwev_sport;	/* Source port */
	uint16_t cfwev_dport;	/* Dest. port */
	in6_addr_t cfwev_saddr;	/* Can be clever later with unions, w/not. */
	in6_addr_t cfwev_daddr;
	/* XXX KEBE ASKS hrtime for relative time from some start instead? */
	struct timeval cfwev_tstamp;
	zoneid_t cfwev_zonedid;	/* Pullable from ipf_stack_t. */
	uint32_t cfwev_ruleid;	/* Pullable from fr_info_t. */
} cfwev_t;

#ifdef _KERNEL
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
 * ipf_block_zstatelog()
 *
 * Called by fr_check().  Record drop events for a global-zone data collector.
 * Use rest-of-ipf-style names for the parameters.
 *
 * XXX KEBE SAYS USE-STATE entry point, but also a subroutine of USE-CALL.
 */
void
ipf_block_zstatelog(frentry_t *fr, fr_info_t *fin, ipf_stack_t *ifs)
{
	cfwev_t event = {0};

	ASSERT3U(ifs->ifs_zstate_enabled, !=, IPF_ZSTATE_NONE);

	/* We need a rule. */
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

	DTRACE_PROBE1(ipf__zstate__block, cfwev_t *, &event);
}

/*
 * ipf_log_zstatelog()
 *
 * Twin of ipstate_log() below, but records state events for a global-zone
 * data collector.
 *
 * XXX KEBE SAYS USE-STATE entry point.
 */
void
ipf_log_zstatelog(struct ipstate *is, uint_t type, ipf_stack_t *ifs)
{
	cfwev_t event = {0};

	ASSERT3U(ifs->ifs_zstate_enabled, ==, IPF_ZSTATE_STATE);

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
		event.cfwev_type = CFWEV_END;
		break;
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

	/* XXX KEBE SAYS Then we do something with it. */
	DTRACE_PROBE1(ipf__zstate__state, cfwev_t *, &event);
}

/*
 * XXX KEBE SAYS EVERYTHING BELOW THIS COMMENT IS USE-CALL EXCLUSIVE!
 */

/*
 * XXX KEBE ASKS MOVE THIS TO A HEADER FILE?
 */

typedef struct ipf_zstate_bucket_s {
	kmutex_t ipfzsb_lock;
	avl_tree_t ipfzsb_tree;
} ipf_zstate_bucket_t;

/*
 * zstate flows: distinct address layouts for IPv4 vs. IPv6 because you can do
 * IPv4 5-tuple comparisons with two uint64_t compares, vs. five of them for
 * IPv6.
 */
typedef struct ipf_zflow_s {
	/* Linkage */
	avl_node_t ipfzfl_node;
	ipf_zstate_bucket_t *ipfzfl_bucket;

	/* Search key. */
	union {
		struct {
			in_addr_t as_laddr;
			in_addr_t as_faddr;
		} au_addrs4;
		struct {
			in6_addr_t as_laddr;
			in6_addr_t as_faddr;
		} au_addrs6;
		uint64_t au_all[4];
	} ipfzfl_addrsu;

	union {
		uint64_t ppu_all;
		struct {
			uint16_t ppue_lport;
			uint16_t ppue_dport;
			uint8_t ppue_protocol;
			uint_t ppue_mbz[3];
		} ppu_elements;
	} ipfzfl_portprotocolu;

	/* Other state... */
	hrtime_t ipfzfl_expiry;
	uint8_t ipfzfl_direction;
	uint8_t ipfzfl_tcphandshake;
	uint32_t ipfzfl_refcnt;
	uint32_t ipfzfl_ruleid;
} ipf_zflow_t;
#define	ipfzfl_addrs4 ipfzfl_addrsu.au_all[0]
#define	ipfzfl_laddr4 ipfzfl_addrsu.au_addrs4.as_laddr
#define	ipfzfl_faddr4 ipfzfl_addrsu.au_addrs4.as_faddr
#define	ipfzfl_addrs6 ipfzfl_addrsu.au_all
#define	ipfzfl_laddr6 ipfzfl_addrsu.au_addrs6.as_laddr
#define	ipfzfl_faddr6 ipfzfl_addrsu.au_addrs6.as_faddr
#define	ipfzfl_portprotocol ipfzfl_portprotocolu.ppu_all
#define	ipfzfl_lport ipfzfl_portprotocolu.ppu_elements.ppue_lport
#define	ipfzfl_fport ipfzfl_portprotocolu.ppu_elements.ppue_fport
#define	ipfzfl_protocol ipfzfl_portprotocolu.ppu_elements.ppue_protocol
#define	ipfzfl_mbz ipfzfl_portprotocolu.ppu_elements.ppue_mbz

static void
ipf_zflow_refhold(ipf_zflow_t *ipfzfl)
{
	atomic_inc_32(&ipfzfl->ipfzfl_refcnt);
	ASSERT(ipfzfl->ipfzfl_refcnt != 0);
}

static void
ipf_zflow_refrele(ipf_zflow_t *ipfzfl)
{
	ASSERT(ipfzfl->ipfzfl_refcnt != 0);
	membar_exit();
	if (atomic_dec_32_nv(&ipfzfl->ipfzfl_refcnt) == 0)
		kmem_free(ipfzfl, sizeof (*ipfzfl));
}

/*
 * For now, xor all the bytes into a uint8_t. This May Change.
 * The stock ipf state tracking does 5000-6000 linked-list buckets.
 * We're doing 256 AVL trees.
 */
static inline uint8_t
zstate_hash(uint32_t *laddr, uint32_t *faddr, uint16_t lport, uint16_t rport,
    uint8_t protocol, uint8_t version)
{
	uint8_t results = protocol;
	uint32_t acc32 =
	    *laddr ^ *faddr ^ ((uint32_t)lport) ^ ((uint32_t)rport);

	if (version == IPV6_VERSION) {
		acc32 ^= laddr[1];
		acc32 ^= laddr[2];
		acc32 ^= laddr[3];
		acc32 ^= faddr[1];
		acc32 ^= faddr[2];
		acc32 ^= faddr[3];
	}

	results ^= (acc32 >> 24) ^ (acc32 >> 16) ^ (acc32 >> 8) ^ acc32;

	return (results);
}

#define IPFZS_BUCKETS 256

/* Allocated and assigned to the ifs_zstate_trackers. */
typedef struct ipf_zstate_s {
	ipf_zstate_bucket_t ipfzs_v4[IPFZS_BUCKETS];
	ipf_zstate_bucket_t ipfzs_v6[IPFZS_BUCKETS];
	/* XXX KEBE ASKS kmem_cache? */
} ipf_zstate_t;

void
ipf_zstate_clear(ipf_stack_t *ifs)
{
	int i;
	ipf_zstate_t *zstate = (ipf_zstate_t *)ifs->ifs_zstate_trackers;

	if (ifs->ifs_zstate_trackers == NULL)
		return;

	ifs->ifs_zstate_trackers = NULL;

	/* XXX KEBE SAYS FILL ME IN! */
	ASSERT3U(ifs->ifs_zstate_enabled, ==, IPF_ZSTATE_CALL);

	for (i = 0; i < IPFZS_BUCKETS; i++) {
		ipf_zflow_t *ipfzfl;
		void *cookie;
		avl_tree_t *tree;

		/* XXX KEBE ASKS - Assume we're good and don't need locking? */
		mutex_destroy(&zstate->ipfzs_v4[i].ipfzsb_lock);
		cookie = NULL;
		tree = &zstate->ipfzs_v4[i].ipfzsb_tree;
		while ((ipfzfl = avl_destroy_nodes(tree, &cookie)) != NULL)
			ipf_zflow_refrele(ipfzfl);
		mutex_destroy(&zstate->ipfzs_v6[i].ipfzsb_lock);
		cookie = NULL;
		tree = &zstate->ipfzs_v6[i].ipfzsb_tree;
		while ((ipfzfl = avl_destroy_nodes(tree, &cookie)) != NULL)
			ipf_zflow_refrele(ipfzfl);
	}

	kmem_free(zstate, sizeof (*zstate));
}

static int
ipf_zstate_v4cmp(const void *l, const void *r)
{
	ipf_zflow_t *lflow, *rflow;
	uint64_t lportproto, rportproto, laddrs, raddrs;

	lflow = (ipf_zflow_t *)l;
	rflow = (ipf_zflow_t *)r;

#if 1
	/* Compare by protocol & port first. */
	lportproto = lflow->ipfzfl_portprotocol;
	rportproto = rflow->ipfzfl_portprotocol;
	if (lportproto > rportproto)
		return (1);
	if (lportproto < rportproto)
		return (-1);

	laddrs = lflow->ipfzfl_addrs4;
	raddrs = rflow->ipfzfl_addrs4;
	if (laddrs > raddrs)
		return (1);
	if (laddrs < raddrs)
		return (-1);
	return (0);
#else
	/* Compare by addresses first. */
	laddrs = lflow->ipfzfl_addrs4;
	raddrs = rflow->ipfzfl_addrs4;
	if (laddrs > raddrs)
		return (1);
	if (laddrs < raddrs)
		return (-1);

	lportproto = lflow->ipfzfl_portprotocol;
	rportproto = rflow->ipfzfl_portprotocol;
	if (rportproto > rportproto)
		return (1);
	if (laddrs < raddrs)
		return (-1);
	return (0);
#endif
}

static int
ipf_zstate_v6cmp(const void *l, const void *r)
{
	ipf_zflow_t *lflow, *rflow;
	uint64_t lportproto, rportproto, *laddrs, *raddrs;

	lflow = (ipf_zflow_t *)l;
	rflow = (ipf_zflow_t *)r;

	/*
	 * For IPv6 address comparison, we don't need to SORT as much as
	 * DIFFERENTIATE.  To that end, compare the LOW 64-bits first, as
	 * they are far more likely to be different.  Our goal is to get
	 * out of this function as quickly as possible.
	 */

#if 1
	/* Compare by protocol & port first. */
	lportproto = lflow->ipfzfl_portprotocol;
	rportproto = rflow->ipfzfl_portprotocol;
	if (lportproto > rportproto)
		return (1);
	if (lportproto < rportproto)
		return (-1);
	
	laddrs = lflow->ipfzfl_addrs6;
	raddrs = rflow->ipfzfl_addrs6;
	if (laddrs[1] > raddrs[1])
		return (1);
	if (laddrs[1] < raddrs[1])
		return (-1);
	/* As of here, we know [lr]addrs[1] are equal. */
	if (laddrs[0] > raddrs[0])
		return (1);
	if (laddrs[0] < raddrs[0])
		return (-1);
	return (0);
#else
	/* Compare by addresses first. */
	laddrs = lflow->ipfzfl_addrs4;
	raddrs = rflow->ipfzfl_addrs4;
	if (laddrs[1] > raddrs[1])
		return (1);
	if (laddrs[1] < raddrs[1])
		return (-1);
	/* As of here, we know [lr]addrs[1] are equal. */
	if (laddrs[0] > raddrs[0])
		return (1);
	if (laddrs[0] < raddrs[0])
		return (-1);

	lportproto = lflow->ipfzfl_portprotocol;
	rportproto = rflow->ipfzfl_portprotocol;
	if (rportproto > rportproto)
		return (1);
	if (laddrs < raddrs)
		return (-1);
	return (0);
#endif
}

int
ipf_zstate_init(frentry_t *fr, ipf_stack_t *ifs)
{
	int i;
	ipf_zstate_t *zstate;

	if (ifs->ifs_zstate_trackers != NULL ||
	    ifs->ifs_zstate_enabled != IPF_ZSTATE_CALL) {
		return (0);
	}

	zstate = kmem_alloc(sizeof (*zstate), KM_SLEEP);
	for (i = 0; i < IPFZS_BUCKETS; i++) {
		mutex_init(&(zstate->ipfzs_v4[i].ipfzsb_lock), NULL,
		    MUTEX_DEFAULT, NULL);
		avl_create(&(zstate->ipfzs_v4[i].ipfzsb_tree),
		    ipf_zstate_v4cmp, sizeof (ipf_zflow_t),
		    offsetof(ipf_zflow_t, ipfzfl_node));
		mutex_init(&(zstate->ipfzs_v6[i].ipfzsb_lock), NULL,
		    MUTEX_DEFAULT, NULL);
		avl_create(&(zstate->ipfzs_v6[i].ipfzsb_tree),
		    ipf_zstate_v6cmp, sizeof (ipf_zflow_t),
		    offsetof(ipf_zflow_t, ipfzfl_node));
	}

	ifs->ifs_zstate_trackers = zstate;

	return (0);
}

frentry_t *
ipf_zstate_pass(fr_info_t *fin, uint32_t *passp)
{

	ASSERT3U(fin->fin_ifs->ifs_zstate_enabled, ==, IPF_ZSTATE_CALL);

	/* XXX KEBE SAYS FILL ME IN! See ~/notes.. */
	

	/*
	 * You need to scribble into *passp what all pass flags need to be
	 * there.
	 */
	*passp |= FR_PASS;
	/* Return the rule already recorded in the packet. */
	return (fin->fin_fr);
}

frentry_t *
ipf_zstate_block(fr_info_t *fin, uint32_t *passp)
{
	ipf_stack_t *ifs = fin->fin_ifs;
	frentry_t *fr = fin->fin_fr;

	ASSERT(ifs != NULL);
	ASSERT(fr != NULL);
	ASSERT3U(ifs->ifs_zstate_enabled, ==, IPF_ZSTATE_CALL);
	ASSERT(ifs->ifs_gz_controlled);

	/* Block is a no-brainer, just log it! */
	ipf_block_zstatelog(fr, fin, ifs);

	/*
	 * You need to scribble into *passp what all block flags need to be
	 * there.
	 */
	*passp |= FR_BLOCK;
	/* Return the rule already recorded in the packet. */
	return (fr);
}
#else
/* Blank stubs to satisfy userland's test stuff. */

int
ipf_zstate_init(frentry_t *a, ipf_stack_t *b)
{
	return (0);
}

frentry_t *
ipf_zstate_pass(fr_info_t *a, uint32_t *b)
{
	return (NULL);
}

frentry_t *
ipf_zstate_block(fr_info_t *a, uint32_t *b)
{
	return (NULL);
}

void
ipf_zstate_clear(ipf_stack_t *a)
{
}

void
ipf_log_zstatelog(struct ipstate *a, uint_t b, ipf_stack_t *c)
{
}

void
ipf_block_zstatelog(frentry_t *a, fr_info_t *b, ipf_stack_t *c)
{
}

#endif	/* _KERNEL */
