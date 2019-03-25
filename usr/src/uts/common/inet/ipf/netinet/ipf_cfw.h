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

#ifndef	__IPF_CFW_H__
#define	__IPF_CFW_H__

#include <sys/types.h>
#include <inet/ip6.h>
#include <sys/uuid.h>

/* Because ipf compiles this kernel file in userland testing... */
#ifndef ASSERT3U
#define	ASSERT3U(a, b, c) ASSERT(a ## b ## c);
#endif	/* ASSERT3U */

/*
 * CFW Event.  Emitted to a global-zone listener. The global-zone listern
 * solves the one-fd-per-zone problem of using each zone's ipmon.
 *
 * These should be 64-bit aligned. There are reserved fields to insure it.
 */
#define	CFWEV_BLOCK	1
#define	CFWEV_BEGIN	2
#define	CFWEV_END	3
#define	CFWDIR_IN	1
#define	CFWDIR_OUT	2

typedef struct cfwev_s {
	uint16_t cfwev_type;	/* BEGIN, END, BLOCK */
	uint16_t cfwev_length;	/* in bytes, so capped to 65535 bytes */
	zoneid_t cfwev_zonedid;	/* Pullable from ipf_stack_t. */

	uint16_t cfwev_ruleid;	/* Pullable from fr_info_t. */
	uint8_t cfwev_protocol;	/* IPPROTO_* */
	/* "direction" informs if src/dst are local/remote or remote/local. */
	uint8_t cfwev_direction;
	uint16_t cfwev_sport;	/* Source port */
	uint16_t cfwev_dport;	/* Dest. port */

	in6_addr_t cfwev_saddr;	/* IPv4 addresses are V4MAPPED. */
	in6_addr_t cfwev_daddr;

	/* XXX KEBE ASKS hrtime for relative time from some start instead? */
	/*
	 * XXX KEBE ALSO ASKS --> we allowing this to be used by 32-bit apps?
	 * If NOT, then we're cool. IF SO, we have a 32/64 problem.
	 */
	struct timeval cfwev_tstamp;

	uuid_t cfwev_ruleuuid;	/* Pullable from fr_info_t. */
} cfwev_t;



#endif	/* __IPF_CFW_H__ */
