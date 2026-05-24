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
		
	}
}

static void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface){

}

