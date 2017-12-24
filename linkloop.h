/*
 * Written by Oron Peled <oron@actcom.co.il>
 *
 * Some code snippets adapted from spak
 * (http://www.xenos.net/software/spak/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#ifndef	LINKLOOP_H
#define	LINKLOOP_H

#include <netinet/if_ether.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <linux/if_packet.h>



#define	PACK_SIZE	1514	/* This is what HPUX sends and responds to */

#define	MAX_IFACES	20

/* Describe an 802.2LLC packet */
struct llc {
		unsigned char dsap;
		unsigned char ssap;
		unsigned char ctrl;
};
struct llc_packet {
	struct ether_header eth_hdr;
	u_int16_t vlan_id; //add vlan header
	u_int16_t vlan_length; //add vlan header
	struct llc llc;
	/* Some test data */
	unsigned char data[PACK_SIZE - sizeof(struct llc) - sizeof(struct ether_header) - sizeof(u_int32_t)];
};

struct llc_packet_strip_vlan {
	struct ether_header eth_hdr;
	struct llc llc;
	/* Some test data */
	unsigned char data[PACK_SIZE - sizeof(struct llc) - sizeof(struct ether_header) - sizeof(u_int32_t)];
};

#define	TEST_CMD	0xE3	/* From 802.2LLC (HPUX sends 0xF3) */

void dump_packet(struct llc_packet_strip_vlan *pack);
char *mac2str(u_int8_t *s);
int parse_address(u_int8_t mac[], const char *str);
void get_hwaddr(int sock, const char name[], u_int8_t mac[]);
void mk_test_packet(struct llc_packet *pack, const u_int8_t src[], const u_int8_t dst[], size_t len, int response, u_int16_t vlan_reply);
void mk_test_packet_strip_vlan(struct llc_packet_strip_vlan *pack, const u_int8_t src[], const u_int8_t dst[], size_t len, int response, u_int16_t vlan_reply);
void send_packet(int sock, const char iface[], const u_int8_t *mac_src, const u_int8_t *mac_dst, struct llc_packet *pack);
void send_packet_strip_vlan(int sock, const char iface[], const u_int8_t *mac_src, const u_int8_t *mac_dst, struct llc_packet_strip_vlan *pack);
int recv_packet(int sock, struct llc_packet_strip_vlan *pack);

#endif	/* LINKLOOP_H */
