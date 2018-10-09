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

/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * NAT engine.  Mappings, 1-1 The rules in vxlnat_rules.c are only consulted
 * if the 1-1 map (kept here) misses or if the outbound lookup (vnetid,
 * protocol, src-IP, dst-IP, src-port, dst-port) misses.
 *
 * The plan is for inbound to hit conn_ts, whose conn_private points to
 * entries here.  The conn_recv* functions live here too (for now).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ksynch.h>
#include <sys/ksocket.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/dtrace.h>
#include <sys/errno.h>
#include <sys/tihdr.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/udp_impl.h>
#include <inet/tcp.h>

#include <inet/vxlnat_impl.h>

static boolean_t vxlnat_vxlan_input(ksocket_t, mblk_t *, size_t, int, void *);
static mblk_t *vxlnat_fixed_fixv4(mblk_t *mp, vxlnat_fixed_t *fixed,
    boolean_t to_private);

/*
 * Initialized to NULL, read/write protected by vxlnat_mutex.
 * Receive functions shouldn't have to access this directly.
 */
ksocket_t vxlnat_underlay;
ire_t *vxlnat_underlay_ire;

void
vxlnat_closesock(void)
{
	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	if (vxlnat_underlay_ire != NULL) {
		ire_refrele(vxlnat_underlay_ire);
		vxlnat_underlay_ire = NULL;
	}
	if (vxlnat_underlay != NULL) {
		(void) ksocket_close(vxlnat_underlay, zone_kcred());
		vxlnat_underlay = NULL;
	}
}

static int
vxlnat_opensock(in6_addr_t *underlay_ip)
{
	int rc, val;
	/* Assume rest is initialized to 0s. */
	struct sockaddr_in6 sin6 = {AF_INET6, BE_16(IPPORT_VXLAN)};
	ip_stack_t *ipst = vxlnat_netstack->netstack_ip;

	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	/* Open... */
	rc = ksocket_socket(&vxlnat_underlay, AF_INET6, SOCK_DGRAM, 0,
	    KSOCKET_SLEEP, zone_kcred());
	if (rc != 0)
		return (rc);

	/* Bind... */
	sin6.sin6_addr = *underlay_ip;
	rc = ksocket_bind(vxlnat_underlay, (struct sockaddr *)(&sin6),
	    sizeof (sin6), zone_kcred());
	if (rc != 0) {
		vxlnat_closesock();
		return (rc);
	}

	/* Use source-port hashing when sending packets out VXLAN... */
	val = UDP_HASH_VXLAN;
	rc = ksocket_setsockopt(vxlnat_underlay, IPPROTO_UDP,
	    UDP_SRCPORT_HASH, &val, sizeof (val), kcred);
	if (rc != 0) {
		vxlnat_closesock();
		return (rc);
	}

	/*
	 * Grab the IRE for underlay address.
	 */
	ASSERT3P(vxlnat_underlay_ire, ==, NULL);
	vxlnat_underlay_ire = (IN6_IS_ADDR_V4MAPPED(underlay_ip)) ?
	    ire_ftable_lookup_simple_v4(underlay_ip->_S6_un._S6_u32[3],
	    0, ipst, NULL) :
	    ire_ftable_lookup_simple_v6(underlay_ip, 0, ipst, NULL);
	if (vxlnat_underlay_ire == NULL) {
		DTRACE_PROBE1(vxlnat__opensock__ire__fail, in6_addr_t *,
		    underlay_ip);
		vxlnat_closesock();
		return (EADDRNOTAVAIL);
	}

	/* Once we return from this, start eating data. */
	rc = ksocket_krecv_set(vxlnat_underlay, vxlnat_vxlan_input, NULL);
	if (rc != 0) {
		vxlnat_closesock();
	}

	return (rc);
}

/*
 * Establish a VXLAN-listening kernel socket.
 * XXX KEBE ASKS ==> Support more than one VXLAN address?
 */
/* ARGSUSED */
int
vxlnat_vxlan_addr(in6_addr_t *underlay_ip)
{
	int rc;

	ASSERT(MUTEX_HELD(&vxlnat_mutex));
	/* For now, we make this a one-underlay-address-only solution. */
	vxlnat_closesock();
	rc = vxlnat_opensock(underlay_ip);
	return (rc);
}

/*
 * Free a remote VXLAN destination.
 */
void
vxlnat_remote_free(vxlnat_remote_t *remote)
{
	ASSERT0(remote->vxnrem_refcount);

	kmem_free(remote, sizeof (*remote));
}

/*
 * Like other unlink functions, assume the appropriate lock is held.
 */
void
vxlnat_remote_unlink(vxlnat_remote_t *remote)
{
	vxlnat_vnet_t *vnet = remote->vxnrem_vnet;

	ASSERT3P(vnet, !=, NULL);
	ASSERT(MUTEX_HELD(&vnet->vxnv_remote_lock));

	/* First unlink so nobody else can find me */
	avl_remove(&vnet->vxnv_remotes, remote);

	/*
	 * We still hold a vnet reference, so races shouldn't be a problem.
	 * Still, for added safety, NULL it out first.
	 */
	remote->vxnrem_vnet = NULL;  /* Condemn this entry. */
	VXNV_REFRELE(vnet);
	VXNREM_REFRELE(remote);	/* Internment release. */
}

/*
 * Find or create a remote VXLAN destination.
 */
static vxlnat_remote_t *
vxlnat_get_remote(vxlnat_vnet_t *vnet, in6_addr_t *remote_addr,
    boolean_t create_on_miss)
{
	vxlnat_remote_t *remote, searcher;
	avl_index_t where;

	searcher.vxnrem_addr = *remote_addr;
	mutex_enter(&vnet->vxnv_remote_lock);
	remote = avl_find(&vnet->vxnv_remotes, &searcher, &where);
	if (remote == NULL && create_on_miss) {
		/* Not as critical if we can't allocate here. */
		remote = kmem_zalloc(sizeof (*remote),
		    KM_NOSLEEP | KM_NORMALPRI);
		if (remote != NULL) {
			remote->vxnrem_addr = *remote_addr;
			remote->vxnrem_refcount = 1; /* Internment reference. */
			VXNV_REFHOLD(vnet);
			remote->vxnrem_vnet = vnet;
			/* Rest is filled in by caller. */
			avl_insert(&vnet->vxnv_remotes, remote, where);
		}
	}
	if (remote != NULL)
		VXNREM_REFHOLD(remote);
	mutex_exit(&vnet->vxnv_remote_lock);
	return (remote);
}

/*
 * Cache inbound packet information in the vnet's remotes section.
 *
 * NOTE: This function assumes a trustworthy underlay network.  If the
 * underlay isn't trustworthy, this function should be renamed, and reduced to
 * a "strip and reality-check the ethernet header" function.
 *
 * Caller has stripped any pre-ethernet data from mp.  We return mp
 * stripped down to its IP header.
 */
static mblk_t *
vxlnat_cache_remote(mblk_t *mp, struct sockaddr_in6 *underlay_src,
    vxlnat_vnet_t *vnet)
{
	struct ether_vlan_header *evh;
	struct ether_header *eh;
	vxlnat_remote_t *remote;
	uint16_t vlan, ethertype;
	ether_addr_t remote_ether;
	ipha_t *ipha;
	ip6_t *ip6h;
	in6_addr_t remote_addr;

	/* Assume (for now) we have at least a VLAN header's worth of data. */
	if (MBLKL(mp) < sizeof (*evh)) {
		/* XXX KEBE ASKS - should we be more forgiving? */
		DTRACE_PROBE1(vxlnat__in__drop__etherhdr, mblk_t *, mp);
		freemsg(mp);
		return (NULL);
	}

	eh = (struct ether_header *)mp->b_rptr;
	ethertype = ntohs(eh->ether_type);
	ether_copy(&eh->ether_shost, &remote_ether);
	if (ethertype == ETHERTYPE_VLAN) {
		evh = (struct ether_vlan_header *)eh;
		/* Keep it in network order... */
		vlan = evh->ether_tci;
		ethertype = ntohs(evh->ether_type);
		ASSERT(vlan != 0);
		mp->b_rptr += sizeof (*evh);
	} else {
		evh = NULL;
		vlan = 0;
		mp->b_rptr += sizeof (*eh);
	}
	if (ethertype != ETHERTYPE_IP && ethertype != ETHERTYPE_IPV6) {
		/*
		 * XXX KEBE SAYS for now, don't handle non-IP packets.
		 * This includes ARP.
		 */
		DTRACE_PROBE1(vxlnat__in__drop__nonip, mblk_t *, mp);
		freemsg(mp);
		return (NULL);
	}

	/* Handle case of split ether + IP headers. */
	if (MBLKL(mp) < sizeof (ipha_t)) {
		mblk_t *freemp;
		
		if (MBLKL(mp) > 0 || mp->b_cont == NULL) {
			/* The IP header is split ACROSS MBLKS! Bail for now. */
			DTRACE_PROBE1(vxlnat__in__drop__splitip, mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		freemp = mp;
		mp = mp->b_cont;
		freeb(freemp);
	}
	/* LINTED -- alignment... */
	ipha = (ipha_t *)mp->b_rptr;

	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		if (ethertype != ETHERTYPE_IP) {
			/* XXX KEBE ASKS - should we be more forgiving? */
			DTRACE_PROBE1(vxlnat__in__drop__etherhdr4,
			    mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &remote_addr);
	} else {
		if (ethertype != ETHERTYPE_IPV6 ||
		    IPH_HDR_VERSION(ipha) != IPV6_VERSION ||
		    MBLKL(mp) < sizeof (ip6_t)) {	
			/* XXX KEBE ASKS - should we be more forgiving? */
			DTRACE_PROBE1(vxlnat__in__drop__etherhdr6,
			    mblk_t *, mp);
			freemsg(mp);
			return (NULL);
		}
		ip6h = (ip6_t *)ipha;
		remote_addr = ip6h->ip6_src;
	}

	/* Find remote and replace OR create new remote. */
	remote = vxlnat_get_remote(vnet, &remote_addr, B_TRUE);
	if (remote != NULL) {
		/*
		 * See if this entry needs fixing or filling-in.  This might
		 * get a bit racy with read-only threads that actually
		 * transmit, but it only means dropped-packets in the worst
		 * case.
		 *
		 * It's THIS PART that inspires the warning about trusting the
		 * underlay network.
		 *
		 * XXX KEBE ASKS -- should we just replace things w/o checking?
		 */
		/* Replace the ethernet address? */
		if (ether_cmp(&remote->vxnrem_ether, &remote_ether) != 0)
			ether_copy(&remote_ether, &remote->vxnrem_ether);
		/*
		 * Replace the underlay? NOTE: Fix if/when underlay becomes
		 * IPv6.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&remote->vxnrem_uaddr,
		    &underlay_src->sin6_addr)) {
			remote->vxnrem_uaddr = underlay_src->sin6_addr;
		}
		/* Replace the vlan ID. Maintain network order... */
		if (remote->vxnrem_vlan != vlan)
			remote->vxnrem_vlan = vlan;
	}
	/*
	 * Else just continue and pray for better luck on another packet or
	 * on the return flight.  It is IP, we can Just Drop It (TM)...
	 */

	/* We're done with the remote entry now. */
	VXNREM_REFRELE(remote);

	/* Advance rptr to the inner IP header and proceed. */
	mp->b_rptr = (uint8_t *)ipha;
	return (mp);
}

/*
 * Process exactly one VXLAN packet.
 */
static void
vxlnat_one_vxlan(mblk_t *mp, struct sockaddr_in6 *underlay_src)
{
	vxlan_hdr_t *vxh;
	vxlnat_vnet_t *vnet;
	ipha_t *ipha;
	ip6_t *ip6h;
	vxlnat_fixed_t *fixed, fsearch;

	if (MBLKL(mp) < sizeof (*vxh)) {
		/* XXX KEBE ASKS -- should we be more forgiving? */
		DTRACE_PROBE1(vxlnat__in__drop__vxlsize, mblk_t *, mp);
		freemsg(mp);
		return;
	}
	vxh = (vxlan_hdr_t *)mp->b_rptr;

	/* If we start using more than just the one flag, fix it. */
	if (vxh->vxlan_flags != VXLAN_F_VDI_WIRE) {
		DTRACE_PROBE1(vxlnat__in__drop__VDI, mblk_t *, mp);
		freemsg(mp);
		return;
	}

	/* Remember, we key off of what's on the wire. */
	vnet = vxlnat_get_vnet(VXLAN_ID_WIRE32(vxh->vxlan_id), B_FALSE);
	if (vnet == NULL) {
		DTRACE_PROBE1(vxlnat__in__drop__vnetid, uint32_t,
		    VXLAN_ID_HTON(VXLAN_ID_WIRE32(vxh->vxlan_id)));
		freemsg(mp);
		return;
	}

	DTRACE_PROBE2(vxlnat__in__vnet, uint32_t,
	    VXLAN_ID_HTON(VXLAN_ID_WIRE32(vxh->vxlan_id)),
	    vxlnat_vnet_t, vnet);

	/*
	 * Off-vxlan processing steps:
	 * 1.) Locate the ethernet header and check/update/add-into remotes.
	 * 2.) Search 1-1s, process if hit.
	 * 3.) Search flows, process if hit.
	 * 4.) Search rules, create new flow (or not) if hit.
	 * 5.) Drop the packets.
	 */

	/* 1.) Locate the ethernet header and check/update/add-into remotes. */
	mp->b_rptr += sizeof (*vxh);
	while (MBLKL(mp) == 0) {
		mblk_t *oldmp = mp;

		mp = mp->b_cont;
		freeb(oldmp);
	}
	mp = vxlnat_cache_remote(mp, underlay_src, vnet);
	if (mp == NULL) {
		VXNV_REFRELE(vnet);
		return;
	}

	/* 2.) Search 1-1s, process if hit. */
	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		ip6h = NULL;
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)(&ipha->ipha_src),
		    &fsearch.vxnf_addr);
	} else {
		/* vxlnat_cache_remote() did reality checks... */
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		ip6h = (ip6_t *)ipha;
		ipha = NULL;
		fsearch.vxnf_addr = ip6h->ip6_src;
	}
	rw_enter(&vnet->vxnv_fixed_lock, RW_READER);
	fixed = avl_find(&vnet->vxnv_fixed_ips, &fsearch, NULL);
	if (fixed != NULL)
		VXNF_REFHOLD(fixed);
	rw_exit(&vnet->vxnv_fixed_lock);
	if (fixed != NULL) {
		mblk_t *newmp = NULL;

		/*
		 * XXX KEBE ASKS --> Do MTU check NOW?!  That way, we have
		 * pre-natted data.  One gotcha, external dests may have
		 * different PathMTUs so see below about EMSGSIZE...
		 */

		/* XXX KEBE SAYS -- FILL ME IN... but for now: */
		if (ipha != NULL)
			newmp = vxlnat_fixed_fixv4(mp, fixed, B_FALSE);
		else
			freemsg(mp); /* XXX handle ip6h */

		if (newmp != NULL) {
			ire_t *outbound_ire;
			/* Use C99's initializers for fun & profit. */
			ip_recv_attr_t iras =
			    { IRAF_IS_IPV4 | IRAF_VERIFIED_SRC };

			ASSERT3P(ipha, !=, NULL);
			ASSERT3P(ipha, ==, newmp->b_rptr);
			/* XXX KEBE ASKS, IRR_ALLOCATE okay?!? */
			outbound_ire = ire_route_recursive_dstonly_v4(
			    ipha->ipha_dst, IRR_ALLOCATE,
			    0 /* XXX KEBE SAYS XMIT HINT! */,
			    vxlnat_netstack->netstack_ip);
			if (outbound_ire == NULL) {
				/* Bail! */
				VXNF_REFRELE(fixed);
				VXNV_REFRELE(vnet);
				return;
			}

			iras.ira_ip_hdr_length = IPH_HDR_LENGTH(ipha);
			if (iras.ira_ip_hdr_length > sizeof (ipha_t))
				iras.ira_flags |= IRAF_IPV4_OPTIONS;
			iras.ira_xmit_hint = 0; /* XXX KEBE SAYS FIX ME! */
			iras.ira_zoneid = outbound_ire->ire_zoneid;
			iras.ira_pktlen = ntohs(ipha->ipha_length);
			iras.ira_protocol = ipha->ipha_protocol;
			/* XXX KEBE ASKS rifindex & ruifindex ?!? */
			/*
			 * NOTE: AT LEAST ira_ill needs ILLF_ROUTER set, as
			 * well as the ill for the external NIC (where
			 * off-link destinations live).  For fixed, ira_ill
			 * should be the ill of the external source.
			 */
			iras.ira_rill = vxlnat_underlay_ire->ire_ill;
			iras.ira_ill = fixed->vxnf_ire->ire_ill;
			/* XXX KEBE ASKS cred & cpid ? */
			iras.ira_verified_src = ipha->ipha_src;
			/* XXX KEBE SAYS don't sweat IPsec stuff. */
			/* XXX KEBE SAYS ALSO don't sweat l2src & mhip */

			/* Okay, we're good! Let's pretend we're forwarding. */
			ire_recv_forward_v4(outbound_ire, mp, ipha, &iras);
			ire_refrele(outbound_ire);
		}

		/* All done... */
		VXNF_REFRELE(fixed);
		VXNV_REFRELE(vnet);
		return;
	}

	/* XXX KEBE SAYS BUILD STEPS 3-4. */

	/* 5.) Nothing, drop the packet. */
	/* XXX KEBE ASKS DIAGNOSTIC? */
	VXNV_REFRELE(vnet);
	freemsg(mp);
}
/*
 * ONLY return B_FALSE if we get a packet-clogging event.
 */
/* ARGSUSED */
static boolean_t
vxlnat_vxlan_input(ksocket_t insock, mblk_t *chain, size_t msgsize, int oob,
    void *ignored)
{
	mblk_t *mp, *nextmp;

	/*
	 * XXX KEBE ASKS --> move hold & release outside of loop?
	 * If so, hold rwlock here.
	 */

	for (mp = chain; mp != NULL; mp = nextmp) {
		struct T_unitdata_ind *tudi;
		struct sockaddr_in6 *sin6;

		nextmp = mp->b_next;
		if (DB_TYPE(mp) != M_PROTO || mp->b_cont == NULL) {
			DTRACE_PROBE1(vxlnat__in__drop__mblk, mblk_t *, mp);
			freemsg(mp);
			continue;
		}

		/* LINTED -- aligned */
		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		if (tudi->PRIM_type != T_UNITDATA_IND) {
			DTRACE_PROBE1(vxlnat__in__drop__TPI, mblk_t *, mp);
			freemsg(mp);
			continue;
		}
		/* LINTED -- aligned */
		sin6 = (struct sockaddr_in6 *)(mp->b_rptr + tudi->SRC_offset);
		VERIFY(sin6->sin6_family == AF_INET6);
		VERIFY(tudi->SRC_length >= sizeof (*sin6));

		vxlnat_one_vxlan(mp->b_cont, sin6);
		freeb(mp);
	}

	return (B_TRUE);
}

/*
 * Use RFC 1141's technique (with a check for -0).
 *
 * newsum = oldsum - (new16a + old16a - new16b + old16b ...);
 *
 * NOTE: "oldsum" is right off the wire in wire-native order.
 * NOTE2: "old" and "new" ALSO point to things in wire-native order.
 * NOTE3:  THIS MUST TAKE A MULTIPLE OF 2 BYTES (i.e. uint16_t array).
 * NOTE4: The 32-bit running sum means we can't take len > 64k.
 */
uint16_t
vxlnat_cksum_adjust(uint16_t oldsum, uint16_t *old, uint16_t *new, uint_t len)
{
	uint32_t newsum = ntohs(oldsum);

	ASSERT((len & 0x1) == 0);
	while (len != 0) {
		newsum -= ntohs(*new);
		newsum += ntohs(*old);
		len -= 2;
		old++;
		new++;
	}
	newsum += (newsum >> 16) & 0xffff;

	return (newsum == 0xffff ? 0 : htons(newsum));
}

/*
 * Fix inner headers on an ICMP packet.
 *
 * XXX KEBE SAYS FOR NOW, just do addresses for 1-1/fixed.  When we do
 * flows, include old_port/new_port as well.
 */
static mblk_t *
vxlnat_fix_icmp_inner_v4(mblk_t *mp, icmph_t *icmph, ipaddr_t old_one,
    ipaddr_t new_one, boolean_t to_private)
{
	mblk_t *newmp;
	ipha_t *inner_ipha;
	ipaddr_t *new_ones_place;

	if ((uint8_t *)(icmph + 1) + sizeof (ipha_t) > mp->b_wptr) {
		/* Pay the pullup tax. */
		newmp = msgpullup(mp, -1);
		freemsg(mp);
		if (newmp == NULL) {
			DTRACE_PROBE1(vxlnat__fixicmp__pullupfail, void *,
			    NULL);
			return (NULL);
		}
		if (MBLKL(newmp) < 2 * sizeof (ipha_t) + sizeof (icmph_t)) {
			/* Wow! Too-tiny ICMP packet. */
			DTRACE_PROBE1(vxlnat__fixicmp__tootiny, mblk_t *,
			    newmp);
			freeb(newmp);
			return (NULL);
		}
		mp = newmp;
		/* Temporarily use inner_ipha for the outer one. */
		inner_ipha = (ipha_t *)mp->b_rptr;
		icmph = (icmph_t *)(mp->b_rptr + IPH_HDR_LENGTH(inner_ipha));
	}
	inner_ipha = (ipha_t *)(icmph + 1);
	new_ones_place = to_private ?
	    &inner_ipha->ipha_src : &inner_ipha->ipha_dst;
	if (*new_ones_place != old_one) {
		/* Either I'm buggy or the packet is. */
		DTRACE_PROBE2(vxlnat__fixicmp__badinneraddr, ipaddr_t,
		    old_one, ipaddr_t, *new_ones_place);
		freeb(mp);
		return (NULL);
	}
	*new_ones_place = new_one;

	/* Adjust ICMP checksum... */
	icmph->icmph_checksum = vxlnat_cksum_adjust(icmph->icmph_checksum,
	    (uint16_t *)&old_one, (uint16_t *)&new_one, sizeof (ipaddr_t));

	/*
	 * XXX KEBE ASKS, recompute *inner-packet* checksums?  Let's not for
	 * now, but consider this Fair Warning (or some other VH album...).
	 */
	return (mp);
}

/*
 * Take a 1-1/fixed IPv4 packet and convert it for transmission out the
 * appropriate end. "to_private" is what it says on the tin.
 */
static mblk_t *
vxlnat_fixed_fixv4(mblk_t *mp, vxlnat_fixed_t *fixed, boolean_t to_private)
{
	ipaddr_t new_one, old_one;
	ipaddr_t *new_ones_place;
	ipha_t *ipha = (ipha_t *)mp->b_rptr;
	uint8_t *nexthdr, *end_wptr;

	if (to_private) {
		IN6_V4MAPPED_TO_IPADDR(&fixed->vxnf_addr, new_one);
		new_ones_place = &ipha->ipha_dst;
	} else {
		IN6_V4MAPPED_TO_IPADDR(&fixed->vxnf_pubaddr, new_one);
		new_ones_place = &ipha->ipha_src;
	}

	old_one = *new_ones_place;
	*new_ones_place = new_one;

	/*
	 * Recompute the IP header checksum, and check for the TCP or UDP
	 * checksum as well, as they'll need recomputing as well.
	 */

	/* First, the IPv4 header itself. */
	ipha->ipha_hdr_checksum = vxlnat_cksum_adjust(ipha->ipha_hdr_checksum,
	    (uint16_t *)&old_one, (uint16_t *)&new_one, sizeof (ipaddr_t));

	nexthdr = (uint8_t *)ipha + IPH_HDR_LENGTH(ipha);
	if (nexthdr >= mp->b_wptr) {
		nexthdr = mp->b_cont->b_rptr +
		    (MBLKL(mp) - IPH_HDR_LENGTH(ipha));
		end_wptr = mp->b_cont->b_wptr;
	} else {
		end_wptr = mp->b_wptr;
	}

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP: {
		tcpha_t *tcph = (tcpha_t *)nexthdr;

		if (nexthdr + sizeof (*tcph) >= end_wptr) {
			/* Bail for now. */
			DTRACE_PROBE1(vxlnat__fix__tcp__mblkspan, mblk_t *,
			    mp);
			freemsg(mp);
			return (NULL);
		}
		tcph->tha_sum = vxlnat_cksum_adjust(tcph->tha_sum,
		    (uint16_t *)&old_one, (uint16_t *)&new_one,
		    sizeof (ipaddr_t));
		break;	/* Out of switch. */
	}
	case IPPROTO_UDP: {
		udpha_t *udph = (udpha_t *)nexthdr;

		if (nexthdr + sizeof (*udph) >= end_wptr) {
			/* Bail for now. */
			DTRACE_PROBE1(vxlnat__fix__udp__mblkspan, mblk_t *,
			    mp);
			freemsg(mp);
			return (NULL);
		}
		udph->uha_checksum = vxlnat_cksum_adjust(udph->uha_checksum,
		    (uint16_t *)&old_one, (uint16_t *)&new_one,
		    sizeof (ipaddr_t));
		break;	/* Out of switch. */
	}
	case IPPROTO_ICMP: {
		icmph_t *icmph = (icmph_t *)nexthdr;

		/*
		 * We need to check the case of ICMP messages that contain
		 * IP packets.  We will need to at least change the addresses,
		 * and *maybe* the checksums too if necessary.
		 *
		 * This may replicate some of icmp_inbound_v4(), alas.
		 */
		if (nexthdr + sizeof (*icmph) >= end_wptr) {
			mblk_t *newmp;
			/*
			 * Unlike the others, we're going to pay the pullup
			 * tax here.
			 */
			newmp = msgpullup(mp, -1);
			freemsg(mp);
			if (newmp == NULL) {
				DTRACE_PROBE1(vxlnat__icmp__pullupfail, void *,
				    NULL);
				return (NULL);
			}
			mp = newmp;
			ipha = (ipha_t *)(mp->b_rptr);
			nexthdr = (uint8_t *)ipha + IPH_HDR_LENGTH(ipha);
			icmph = (icmph_t *)nexthdr;
		}

		switch (icmph->icmph_type) {
		case ICMP_ADDRESS_MASK_REPLY:
		case ICMP_ADDRESS_MASK_REQUEST:
		case ICMP_TIME_STAMP_REPLY:
		case ICMP_TIME_STAMP_REQUEST:
		case ICMP_ECHO_REQUEST:
		case ICMP_ECHO_REPLY:
			/* These merely need to get passed along. */
			break;
		case ICMP_ROUTER_ADVERTISEMENT:
		case ICMP_ROUTER_SOLICITATION:
			/* These shouldn't be traversing a NAT at all. Drop. */
			DTRACE_PROBE1(vxlnat__icmp__cantpass, int,
			    icmph->icmph_type);
			freemsg(mp);
			return (NULL);
		case ICMP_PARAM_PROBLEM:
		case ICMP_TIME_EXCEEDED:
		case ICMP_DEST_UNREACHABLE:
			/* These include inner-IP headers we need to adjust. */
			mp = vxlnat_fix_icmp_inner_v4(mp, icmph, old_one,
			    new_one, to_private);
			break;
		default:
			/* Pass along to receiver, but warn. */
			DTRACE_PROBE1(vxlnat__icmp__unknown, int,
			    icmph->icmph_type);
			break;
		}
	}
	/* Otherwise we can't make any other assumptions for now... */
	default:
		break;
	}

	return (mp);
}

vxlnat_remote_t *
vxlnat_xmit_vxlanv4(mblk_t *mp, in6_addr_t *overlay_dst,
    vxlnat_remote_t *remote, vxlnat_vnet_t *vnet)
{
	struct sockaddr_in6 sin6 = {AF_INET6};
	struct msghdr msghdr = {NULL};
	mblk_t *vlan_mp;
	extern uint_t vxlan_alloc_size, vxlan_noalloc_min;
	vxlan_hdr_t *vxh;
	struct ether_vlan_header *evh;
	int rc;
	cred_t *cred;

	if (remote == NULL || remote->vxnrem_vnet == NULL) {
		DTRACE_PROBE1(vxlnat__xmit__vxlanv4, vxlnat_remote_t *, remote);
		/* Release the condemned remote. */
		if (remote != NULL)
			VXNREM_REFRELE(remote);

		/* See if we have a remote ready to use... */
		remote = vxlnat_get_remote(vnet, overlay_dst, B_FALSE);

		if (remote == NULL) {
			/*
			 * We need to do the moral equivalent of PF_KEY
			 * ACQUIRE or overlay's queue-resolve so that we can
			 * have someone in user-space send me a remote.  Until
			 * then, drop the reference if condemned, free the
			 * message, and return NULL.
			 */

			freemsg(mp);
			return (NULL);
		}
	}
	ASSERT(vnet == remote->vxnrem_vnet);

	if (DB_REF(mp) > 1 || mp->b_rptr - vxlan_noalloc_min < DB_BASE(mp)) {
		vlan_mp = allocb(vxlan_alloc_size, BPRI_HI);
		if (vlan_mp == NULL) {
			DTRACE_PROBE1(vxlnat__xmit__vxlanv4__allocfail,
			    vxlnat_remote_t *, remote);
			freemsg(mp);
			/* Just drop the packet, but don't tell caller. */
			return (remote);
		}
		vlan_mp->b_wptr = DB_LIM(vlan_mp);
		vlan_mp->b_rptr = vlan_mp->b_wptr;
		vlan_mp->b_cont = mp;
	} else {
		vlan_mp = mp;
	}
	vlan_mp->b_rptr -= sizeof (*vxh) + sizeof (*evh);
	vxh = (vxlan_hdr_t *)vlan_mp->b_rptr;
	vxh->vxlan_flags = VXLAN_F_VDI_WIRE;
	vxh->vxlan_id = vnet->vxnv_vnetid;	/* Already in wire-order. */

	/* Fill in the Ethernet header. */
	evh = (struct ether_vlan_header *)(vxh + 1);
	ether_copy(&remote->vxnrem_ether, &evh->ether_dhost);
	/*
	 * XXX KEBE SAYS OH HELL, we need "my entry's" ethernet, which only
	 * exists for nat rules at the moment.  Wing it for now.
	 */
	evh->ether_shost.ether_addr_octet[0] = 0x1;
	evh->ether_shost.ether_addr_octet[1] = 0x2;
	evh->ether_shost.ether_addr_octet[2] = 0x3;
	evh->ether_shost.ether_addr_octet[3] = 0x4;
	evh->ether_shost.ether_addr_octet[4] = 0x5;
	evh->ether_shost.ether_addr_octet[5] = 0x6;
	evh->ether_tpid = htons(ETHERTYPE_VLAN);
	evh->ether_tci = remote->vxnrem_vlan;
	evh->ether_type = htons(ETHERTYPE_IP);

	msghdr.msg_name = (struct sockaddr_storage *)&sin6;
	msghdr.msg_namelen = sizeof (sin6);
	/* Address family and other zeroing already done up top. */
	sin6.sin6_port = htons(IPPORT_VXLAN);
	sin6.sin6_addr = remote->vxnrem_uaddr;
	
	/*
	 * cred_t dance is because we may be getting this straight from
	 * interrupt context.
	 */
	cred = zone_get_kcred(netstack_get_zoneid(vxlnat_netstack));
	if (cred == NULL) {
		DTRACE_PROBE1(vxlnat__xmit__vxlan4__credfail, 
		    vxlnat_remote_t *, remote);
		freemsg(vlan_mp);
	}
	/*
	 * Use MSG_DONTWAIT to avoid blocks, esp. if we're getting this
	 * straight from interrupt context.
	 */
	rc = ksocket_sendmblk(vxlnat_underlay, &msghdr, MSG_DONTWAIT, &vlan_mp,
	    cred);
	crfree(cred);
	if (rc != 0) {
		DTRACE_PROBE2(vxlnat__xmit__vxlan4__sendfail, int, rc,
		    vxlnat_remote_t *, remote);
		freemsg(vlan_mp);
	}
	return (remote);
}

/*
 * New ire_{recv,send}fn implementations if we're doing 1-1 mappings.
 */
int
vxlnat_fixed_ire_send_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	/* XXX KEBE SAYS FILL ME IN, but for now... */
	freemsg(mp);
	return (EOPNOTSUPP);
}

void
vxlnat_fixed_ire_recv_v6(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	/* XXX KEBE SAYS FILL ME IN, but for now... */
	freemsg(mp);
}

/*
 * I believe the common case for this will be from self-generated ICMP
 * messages.  Other same-netstack-originated traffic will also come through
 * here (one internal reaching what turns out to be another internal).
 */
int
vxlnat_fixed_ire_send_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_xmit_attr_t *ixa, uint32_t *identp)
{
	ip_recv_attr_t iras;	/* NOTE: No bzero because we pay more later */
	ipha_t *ipha = (ipha_t *)iph_arg;

	/*
	 * XXX KEBE ASKS, any DTrace probes or other instrumentation that
	 * perhaps should be set?
	 */

	/* Map ixa to ira. */
	iras.ira_pktlen = ixa->ixa_pktlen;
	/* XXX KEBE ASKS more?!? */

	/*
	 * In normal TCP/IP processing, this shortcuts the IP header checksum
	 * AND POSSIBLY THE ULP checksum cases.  Since this is likely to head
	 * back into the internal network, we need to recompute things again.
	 */
	if (!ip_output_sw_cksum_v4(mp, ipha, ixa)) {
		freemsg(mp);
		return (EMSGSIZE);
	}
#if 0
	/* XXX KEBE ASKS Special-case ICMP here? */
	if (ipha->ipha_protocol == IPPROTO_ICMP) {
		icmph_t *icmph;

		icmph = (icmph_t *)((uint8_t *)ipha + IPH_HDR_LENGTH(ipha));
		if ((uint8_t *)icmph >= mp->b_wptr) {
			freemsg(mp);
			return (EMSGSIZE);
		}
		icmph->icmph_checksum = 0;
		icmph->icmph_checksum = IP_CSUM(mp, IPH_HDR_LENGTH(ipha), 0);
	}
#endif

	vxlnat_fixed_ire_recv_v4(ire, mp, iph_arg, &iras);

	return (0);
}

void
vxlnat_fixed_ire_recv_v4(ire_t *ire, mblk_t *mp, void *iph_arg,
    ip_recv_attr_t *ira)
{
	vxlnat_fixed_t *fixed;
	vxlnat_vnet_t *vnet;
	ipha_t *ipha = (ipha_t *)iph_arg;
	int newmtu;

	/* Make a note for DAD that this address is in use */
	ire->ire_last_used_time = LBOLT_FASTPATH;

	/* Only target the IRE_LOCAL with the right zoneid. */
	ira->ira_zoneid = ire->ire_zoneid;

	/*
	 * XXX KEBE ASKS, any DTrace probes or other instrumentation that
	 * perhaps should be set?
	 */

	/*
	 * Reality check some things.
	 */
	fixed = (vxlnat_fixed_t *)ire->ire_dep_sib_next;
	vnet = fixed->vxnf_vnet;

	ASSERT3P(ire, ==, fixed->vxnf_ire);

	if (IRE_IS_CONDEMNED(ire) || vnet == NULL)
		goto detach_ire_and_bail;

	/*
	 * Not a common-case, but a possible one.  If our underlay MTU is
	 * smaller than the external MTU, it is possible that we will have a
	 * size mismatch and therefore need to either fragment at the VXLAN
	 * layer (VXLAN UDP packet sent as two or more IP fragments) OR
	 * if IPH_DF is set, send an ICMP_NEEDS_FRAGMENTATION back to the
	 * sender.  Perform the check here BEFORE we NAT the packet.
	 */
	ASSERT(vxlnat_underlay_ire->ire_ill != NULL);
	newmtu = vxlnat_underlay_ire->ire_ill->ill_mtu - sizeof (ipha_t) -
	    sizeof (udpha_t) - sizeof (vxlan_hdr_t) -
	    sizeof (struct ether_vlan_header);
	if ((ntohs(ipha->ipha_fragment_offset_and_flags) & IPH_DF) &&
	    ntohs(ipha->ipha_length) > newmtu) {
		icmp_frag_needed(mp, newmtu, ira);
		/* We're done.  Assume icmp_frag_needed() consumed mp. */
		return;
	}

	/*
	 * So we're here, and since we have a refheld IRE, we have a refheld
	 * fixed and vnet. Do some of what ip_input_local_v4() does (inbound
	 * checksum?  some ira checks?), but otherwise, swap the destination
	 * address as mapped in "fixed", recompute any checksums, and send it
	 * along its merry way (with a ttl decement too) to a VXLAN
	 * destination.
	 */
	mp = vxlnat_fixed_fixv4(mp, fixed, B_TRUE);
	if (mp == NULL)
		return; /* Assume it's been freed & dtraced already. */

	/*
	 * Otherwise, we're ready to transmit this packet over the vxlan
	 * socket.
	 */
	fixed->vxnf_remote = vxlnat_xmit_vxlanv4(mp, &fixed->vxnf_addr,
	    fixed->vxnf_remote, vnet);
	if (fixed->vxnf_remote == NULL) {
		/* XXX KEBE ASKS, DTrace probe here?  Or in-function? */
		DTRACE_PROBE2(vxlnat__fixed__xmitdrop,
		    in6_addr_t *, &fixed->vxnf_addr,
		    uint32_t, VXLAN_ID_NTOH(vnet->vxnv_vnetid));
	}
	return;

detach_ire_and_bail:
	/* Oh no, something's condemned.  Drop the IRE now. */
	ire->ire_recvfn = ire_recv_local_v4;
	ire->ire_dep_sib_next = NULL;
	VXNF_REFRELE(fixed);
	/* Pass the packet back... */
	ire_recv_local_v4(ire, mp, iph_arg, ira);
	return;
}
