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
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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


uint8_t* construct_arp_reply_packet(struct sr_if* iface, 
                                    struct sr_ethernet_hdr* eth_hdr, 
                                    struct sr_arp_hdr* arp_hdr) 
{

    uint8_t* reply_packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
    if (!reply_packet) {
        perror("malloc failed");
        return NULL;
    }

    struct sr_ethernet_hdr* reply_eth_hdr = (struct sr_ethernet_hdr*) reply_packet;
    struct sr_arp_hdr* reply_arp_hdr = (struct sr_arp_hdr*)(reply_packet + sizeof(struct sr_ethernet_hdr));

    memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = htons(ethertype_arp);

    reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp_hdr->ar_pro = htons(ethertype_ip);
    reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    reply_arp_hdr->ar_pln = 4;
    reply_arp_hdr->ar_op  = htons(arp_op_reply);
    memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = iface->ip;
    memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

    return reply_packet; 
}
void handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
   
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*) packet;
    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    size_t packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);

    if (len < packet_size) {
        printf("ARP packet too short\n");
        return;
    }

    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        printf("Handling ARP request\n");
        
        struct sr_if* head = sr->if_list;
        while (head) {
            if (head->ip == arp_hdr->ar_tip) {
                break;
            }
            head = head->next;
        }

        if (!head) {
            printf("no matching interface)\n");
            return;
        }

        uint8_t* reply_packet = construct_arp_reply_packet(head, eth_hdr, arp_hdr);
        sr_send_packet(sr, reply_packet, packet_size, interface);
        free(reply_packet);
        printf("succesfully Sent ARP reply in ARP Request\n");
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        printf("Handling ARP reply\n");
    } else {
        printf("Unknown ARP operation: %d\n", ntohs(arp_hdr->ar_op));
    }
}

struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip) {
    struct sr_rt* best_match = NULL;
    struct sr_rt* rt_entry = sr->routing_table;
    uint32_t longest_mask = 0;

    while (rt_entry) {
        /* bitwise AND to check if the destination IP matches the route entry   */  
        if ((dest_ip & rt_entry->mask.s_addr) == (rt_entry->dest.s_addr & rt_entry->mask.s_addr)) {
            /* Check if this mask is longer (more specific) */
            if (ntohl(rt_entry->mask.s_addr) > ntohl(longest_mask)) {
                best_match = rt_entry;
                longest_mask = rt_entry->mask.s_addr;
            }
        }
        rt_entry = rt_entry->next;
    }

    return best_match;
}

int is_interface_ip(struct sr_instance* sr, uint32_t ip) {
    struct sr_if* iface = sr->if_list;
    while (iface) {
        if (iface->ip == ip) {
            return 1; 
        }
        iface = iface->next;
    }
    return 0;
}      

void forward_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface,/* lent */
        sr_ip_hdr_t* ip_hdr
    ) {
    /* Forward IP packet */

    /*
    ip_hdr->ttr -= 1;
    if (ip_hdr->ttr == 0) {
        printf("TTL expired, need to send ICMP Time Exceeded\n");
        return;
    }
    TODO: ttr reaches 0 or something
    */
 

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((uint16_t*)ip_hdr, ip_hdr->ip_hl * 4);
    struct sr_rt* rt_entry = longest_prefix_match(sr, ip_hdr->ip_dst);

}

void handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) {
    /* Handle IP packet */
    
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(struct sr_ethernet_hdr));
    uint16_t received_sum = ntohs(ip_hdr->ip_sum);
    int ip_header_len = ip_hdr->ip_hl * 4;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((uint16_t*)ip_hdr, ip_header_len);

    /* TODO: icmp send back or something incase of error */
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr_t)) {
        printf("IP packet too short\n");
        return;
    }
    if (received_sum != ntohs(ip_hdr->ip_sum)) {
        printf("Invalid IP checksum\n");
        return;
    }   

    printf("IP packet passed checksum validation\n");

    if (!is_interface_ip(sr, ip_hdr->ip_dst)) {
        forward_ip_packet(sr, packet, len, interface, ip_hdr);
        return;
    }

    if (ip_hdr->ip_p == ip_protocol_icmp) {
        /* I think this is wrong */
        struct sr_icmp_hdr* icmp_hdr = (struct icmp_hdr*)((uint8_t*)ip_hdr + ip_header_len);
        if (icmp_hdr->icmp_type != ICMP_ECHO_REPLY) { 
            return;
        } 
        printf("ICMP Echo Request received\n");
        /* TODO: send an echo reply to the sending host*/
    }
    else if (ip_hdr->ip_p == PROTOCOL_TCP || ip_hdr->ip_p == PROTOCOL_UDP) {
        printf("TCP/UDP packet received for us, need to send ICMP Port Unreachable\n");
        /* TODO: send an ICMP unreachable */
    }

    return;
}

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

  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
  uint16_t type = ntohs(eth_hdr->ether_type);

  switch(type) {
      case ethertype_arp:
          printf("Received ARP packet\n");
          /* trying to find the truth  */
          /* handle ARP */
          handle_arp_packet(sr, packet, len, interface);
          break;
      case ethertype_ip:
          printf("Received IP packet\n");
          /* handle IP */
          handle_ip_packet(sr, packet, len, interface);
          break;
      default:
          printf("Received packet of unknown type %d\n", type);
          return;
  }



  /* fill in code here */

}/* end sr_ForwardPacket */

