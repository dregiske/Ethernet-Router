/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Declaring helpers */
static void handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
static void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void send_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *out_if);


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	// Check length
	if (len < sizeof(sr_ethernet_hdr_t)) return;

	// Check ether_type
	sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;
	uint16_t etype = ntohs(eth->ether_type);
	if (etype == ethertype_arp) {
		handle_arp(sr, packet, len, interface);
	} else if (etype == ethertype_ip) {
		handle_ip(sr, packet, len, interface);
	} else {

	}

}/* end sr_ForwardPacket */


/* Helper Functions */

static void handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	// Length sanity
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;

	// Locate the ARP header
	sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	// Look up the interface
	struct sr_if *iface = sr_get_interface(sr, interface);
	if (!iface) return;

	// Branch on opcode
	uint16_t op = ntohs(arp->ar_op);

	if (op == arp_op_request) {
		if (arp->ar_tip != iface->ip) return;

		unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
		uint8_t *reply = (uint8_t *)malloc(reply_len);

		sr_ethernet_hdr_t *reply_eth = (sr_ethernet_hdr_t *)reply;
		sr_arp_hdr_t *reply_arp =
			(sr_arp_hdr_t *)(reply + sizeof(sr_ethernet_hdr_t));

		memcpy(reply_eth->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
		memcpy(reply_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
		reply_eth->ether_type = htons(ethertype_arp);

		reply_arp->ar_hrd = htons(arp_hrd_ethernet);
		reply_arp->ar_pro = htons(ethertype_ip);
		reply_arp->ar_hln = 6;
		reply_arp->ar_pln = 4;
		reply_arp->ar_op  = htons(arp_op_reply);
		memcpy(reply_arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
		reply_arp->ar_sip = iface->ip;
		memcpy(reply_arp->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
		reply_arp->ar_tip = arp->ar_sip;

		sr_send_packet(sr, reply, reply_len, interface);
		free(reply);

	} else if (op == arp_op_reply) {
		struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,
		                                           arp->ar_sha,
		                                           arp->ar_sip);
		if (req != NULL) {
			for (struct sr_packet *p = req->packets; p != NULL; p = p->next) {
				struct sr_if *oif = sr_get_interface(sr, p->iface);
				if (!oif) continue;
				sr_ethernet_hdr_t *peth = (sr_ethernet_hdr_t *)p->buf;
				memcpy(peth->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
				memcpy(peth->ether_shost, oif->addr, ETHER_ADDR_LEN);
				sr_send_packet(sr, p->buf, p->len, p->iface);
			}
			sr_arpreq_destroy(&sr->cache, req);
		}
	}
}

static void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){
	// Length sanity
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;

    // Locate IP header
    sr_ip_hdr_t *ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20) return;
    if (len < sizeof(sr_ethernet_hdr_t) + ip_hdr_len) return;

    // Verify IP header checksum
    uint16_t orig_ip_sum = ip->ip_sum;
    ip->ip_sum = 0;
    if (cksum(ip, ip_hdr_len) != orig_ip_sum) {
        ip->ip_sum = orig_ip_sum;
        return;
    }
    ip->ip_sum = orig_ip_sum;

    struct sr_if *target = NULL;
    for (struct sr_if *i = sr->if_list; i != NULL; i = i->next) {
        if (i->ip == ip->ip_dst) {
            target = i;
            break;
        }
    }

    if (target != NULL) {

        if (ip->ip_p != ip_protocol_icmp) return;

        unsigned int icmp_offset = sizeof(sr_ethernet_hdr_t) + ip_hdr_len;
        if (len < icmp_offset + sizeof(sr_icmp_t08_hdr_t)) return;

        sr_icmp_t08_hdr_t *icmp = (sr_icmp_t08_hdr_t *)(packet + icmp_offset);
        unsigned int icmp_len = ntohs(ip->ip_len) - ip_hdr_len;

        uint16_t orig_icmp_sum = icmp->icmp_sum;
        icmp->icmp_sum = 0;
        if (cksum(icmp, icmp_len) != orig_icmp_sum) {
            icmp->icmp_sum = orig_icmp_sum;
            return;
        }

        if (icmp->icmp_type != 8) {
            icmp->icmp_sum = orig_icmp_sum;
            return;
        }

        sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet;

        uint8_t tmp_mac[ETHER_ADDR_LEN];
        memcpy(tmp_mac, eth->ether_dhost, ETHER_ADDR_LEN);
        memcpy(eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth->ether_shost, tmp_mac, ETHER_ADDR_LEN);

        uint32_t tmp_ip = ip->ip_src;
        ip->ip_src = ip->ip_dst;
        ip->ip_dst = tmp_ip;

        ip->ip_ttl = 64;
        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, ip_hdr_len);

        icmp->icmp_type = 0;
        icmp->icmp_sum = 0;
        icmp->icmp_sum = cksum(icmp, icmp_len);

        sr_send_packet(sr, packet, len, interface);

    } else {
        if (ip->ip_ttl <= 1) return;
        ip->ip_ttl--;

        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, ip_hdr_len);

        struct sr_rt *route = NULL;
        for (struct sr_rt *r = sr->routing_table; r != NULL; r = r->next) {
            if (r->dest.s_addr == ip->ip_dst) {
                route = r;
                break;
            }
        }

        if (route == NULL) return;

        struct sr_if *out_if = sr_get_interface(sr, route->interface);
        if (!out_if) return;

        uint32_t next_hop = route->gw.s_addr;

        struct sr_arpreq *req = sr_arpcache_queuereq(
            &sr->cache, next_hop, packet, len, out_if->name);

        if (req->times_sent == 0) {
            send_arp_request(sr, next_hop, out_if);
            req->sent = time(NULL);
            req->times_sent = 1;
        }
    }
}

void send_arp_request(struct sr_instance *sr, uint32_t target_ip, struct sr_if *out_if) {
	unsigned int req_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *buf = (uint8_t *)malloc(req_len);

	sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
	sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

	memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
	eth->ether_type = htons(ethertype_arp);

	arp->ar_hrd = htons(arp_hrd_ethernet);
	arp->ar_pro = htons(ethertype_ip);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op  = htons(arp_op_request);
	memcpy(arp->ar_sha, out_if->addr, ETHER_ADDR_LEN);
	arp->ar_sip = out_if->ip;
	memset(arp->ar_tha, 0, ETHER_ADDR_LEN);
	arp->ar_tip = target_ip;

	sr_send_packet(sr, buf, req_len, out_if->name);
	free(buf);
}

