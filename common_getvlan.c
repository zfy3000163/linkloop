/*
 * Written by Oron Peled <oron@actcom.co.il>
 * 
 * Modified by Dominique Domet de Mont, 2007, Dominique.Domet-de-Mont@hp.com
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 *
 * Some code snippets adapted from spak
 * (http://www.xenos.net/software/spak/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include "config.h"
#include <netinet/in.h>		/* for htons(3)			*/

#if HAVE_ETHER_HOSTTON
#include <netinet/ether.h>	/* for ether_hostton(3)		*/
#endif

#include <net/if.h>		/* for IF_NAMESIZE, IFHWADDRLEN */
#include <sys/ioctl.h>		/* for SIOCGIFHWADDR		*/
#include <stdio.h>
#include <string.h>     	/* for memcmp(3) bzero(3)	*/
#include <stdlib.h>		/* for exit(3)			*/
#include <errno.h>
#include <assert.h>
#include "linkloop.h"

/* These are used to define different data structs... */
#if IFHWADDRLEN != ETH_ALEN
#error "SOMETHING IS VERY FISHY: IFHWADDRLEN != ETH_ALEN"
#endif

int vlan = 1, is_vlan_used = 0;
u_int16_t vlan_reply[1000];

int debug_flag = 0;

void dump_packet(struct llc_packet_strip_vlan *pack) {
	int i;
	u_int8_t *p = (u_int8_t *)pack;
	size_t len = ntohs(pack->eth_hdr.ether_type);

	printf("PACKET DUMP: data size=%d (0x%x)", len, len);
	for(i = 0; i < len; i++, p++) {
		if((i % 16) == 0)
			printf("\n%04x\t", i);
		printf("%02x ", (unsigned)*p);
	}
	printf("\nEND PACKET DUMP\n");
}

char *mac2str(u_int8_t *s) {
	static char buf[3*ETH_ALEN];

	sprintf (buf, "0x%02X%02X%02X%02X%02X%02X",
			s[0], s[1], s[2], s[3], s[4], s[5]);
	return buf;
}

int parse_address(u_int8_t mac[], const char *str) {
	unsigned a, b, c, d, e, f;
	struct ether_addr ea;

	if(sscanf(str,"%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) == 6) {
		/* A colon separated notation */
		mac[0] = (unsigned char) a;
		mac[1] = (unsigned char) b;
		mac[2] = (unsigned char) c;
		mac[3] = (unsigned char) d;
		mac[4] = (unsigned char) e;
		mac[5] = (unsigned char) f;
	} else if(sscanf(str,
			"0x%02x%02x%02x%02x%02x%02x", &a, &b, &c, &d, &e, &f) == 6) {
		/* Hexadecimal notation (like HPUX) */
		mac[0] = (unsigned char) a;
		mac[1] = (unsigned char) b;
		mac[2] = (unsigned char) c;
		mac[3] = (unsigned char) d;
		mac[4] = (unsigned char) e;
		mac[5] = (unsigned char) f;
#if HAVE_ETHER_HOSTTON
	} else if(ether_hostton(str, &ea) == 0) {
		/* A name from /etc/ethers */
		memcpy(mac, ea.ether_addr_octet, 8);
#endif
	} else
		return 0;
	return 1;
}

void get_hwaddr(int sock, const char name[], u_int8_t mac[]) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, name, IF_NAMESIZE - 1);
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		exit(1);
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
}

void mk_test_packet(struct llc_packet *pack, const u_int8_t src[], const u_int8_t dst[], size_t len, int response, u_int16_t vlan_reply) {
	assert(len <= ETH_DATA_LEN);			/* 0x05DC == 1500 */

	int i;

	memcpy(pack->eth_hdr.ether_dhost, dst, IFHWADDRLEN);
	memcpy(pack->eth_hdr.ether_shost, src, IFHWADDRLEN);

	u_int16_t vlan_id = 1;
	if(response){
		vlan_id = vlan_reply;
	}
	else{
		vlan_id = vlan;
	}

	u_int16_t vlan_length = len;
	pack->vlan_id = htons(vlan_id);
	pack->vlan_length = htons(vlan_length);

	pack->eth_hdr.ether_type = htons(0x8100);

	pack->llc.dsap = (response) ? 0x80 : 0x00;
	pack->llc.ssap = (response) ? 0x01 : 0x80;	/* XNS? */
	pack->llc.ctrl = TEST_CMD;			/* TEST */

	if(!response){
		pack->data[1] = (vlan) & 0x00ff;
		pack->data[0] = (vlan >> 8) & 0xff;
		for(i = 2; i < len; i++)
			pack->data[i] = i;
	}
	else{
		pack->data[1] = (vlan_reply) & 0x00ff;
		pack->data[0] = (vlan_reply >> 8) & 0xff;
		for(i = 2; i < len; i++)
			pack->data[i] = i;
	}

        pack->data[3] = 0x1;

}

void mk_test_packet_strip_vlan(struct llc_packet_strip_vlan *pack, const u_int8_t src[], const u_int8_t dst[], size_t len, int response, u_int16_t vlan_reply) {
	assert(len <= ETH_DATA_LEN);			/* 0x05DC == 1500 */

	int i;

	memcpy(pack->eth_hdr.ether_dhost, dst, IFHWADDRLEN);
	memcpy(pack->eth_hdr.ether_shost, src, IFHWADDRLEN);


	pack->eth_hdr.ether_type = htons(len);

	pack->llc.dsap = (response) ? 0x80 : 0x00;
	pack->llc.ssap = (response) ? 0x01 : 0x80;	/* XNS? */
	pack->llc.ctrl = TEST_CMD;			/* TEST */

	for(i = 0; i < len; i++)
		pack->data[i] = i;

        pack->data[3] = 0x0;
}

void send_packet_strip_vlan(int sock, const char iface[], const u_int8_t *mac_src, const u_int8_t *mac_dst, struct llc_packet_strip_vlan * pack) {
	int ret;
        int index = if_nametoindex(iface);
        struct sockaddr_ll sl = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_802_2),
		.sll_ifindex = index,
		.sll_halen = ETH_ALEN,
	};

	memcpy(&sl.sll_addr, mac_dst, ETH_ALEN);

	/* Send the packet */
	ret = sendto(sock, pack, sizeof(*pack), 0, (struct sockaddr *)&sl, sizeof(sl));
	if(ret == -1) {
		perror("sendto");
		exit(1);
	}
	if(ret != sizeof(*pack))
		fprintf(stderr, "Warning: Incomplete packet sent\n");
	if(debug_flag)
		printf("sent TEST packet to %s\n", mac2str(pack->eth_hdr.ether_dhost));
}

void send_packet(int sock, const char iface[], const u_int8_t *mac_src, const  u_int8_t *mac_dst, struct llc_packet * pack) {
        int index = if_nametoindex(iface);
        struct sockaddr_ll sl = {
		.sll_family = AF_INET,
		.sll_protocol = htons(ETH_P_802_2),
		.sll_ifindex = index,
		.sll_halen = ETH_ALEN,
	};

	memcpy(&sl.sll_addr, mac_dst, ETH_ALEN);
	int ret;

	/* Send the packet */
	ret = sendto(sock, pack, sizeof(*pack), 0, (struct sockaddr *)&sl, sizeof(sl));
	if(ret == -1) {
		perror("sendto");
		exit(1);
	}
	if(ret != sizeof(*pack))
		fprintf(stderr, "Warning: Incomplete packet sent\n");
	if(debug_flag)
		printf("sent TEST packet to %s\n", mac2str(pack->eth_hdr.ether_dhost));
}

#define MSG_TRUNC       0x20
int recv_packet(int sock, struct llc_packet_strip_vlan *pack) {
	struct sockaddr_ll sl;
	socklen_t len;
	int ret;
	char pbuf[65535];
	char *ptrbuf = &pbuf;

#if 1
	struct sockaddr_ll      from;
	struct iovec            iov;
	struct msghdr           msg;
	struct cmsghdr          *cmsg;
	union {
                struct cmsghdr  cmsg;
                char            buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
        } cmsg_buf;

	msg.msg_name            = &from;
        msg.msg_namelen         = sizeof(from);
        msg.msg_iov             = &iov;
        msg.msg_iovlen          = 1;
        msg.msg_control         = &cmsg_buf;
        msg.msg_controllen      = sizeof(cmsg_buf);
        msg.msg_flags           = 0;

        iov.iov_len             = sizeof(pbuf);
        iov.iov_base            = ptrbuf;
#endif
	do {
		ret = recvmsg(sock, &msg, MSG_TRUNC);
	}while(ret == -1 && errno == EINTR);

	if(ret){
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct tpacket_auxdata *aux;
                        unsigned int len;
			printf("loop:%d\n", ret);

			if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
                            cmsg->cmsg_level != SOL_PACKET ||
                            cmsg->cmsg_type != PACKET_AUXDATA)
                                continue;


			len = (u_int)ret > iov.iov_len ? iov.iov_len : (u_int)ret;
			if (len < 14)
                                break;
			
			
			aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
			printf("vlan_id:%d, status:%d\n", aux->tp_vlan_tci, aux->tp_status);
			if ((aux->tp_vlan_tci == 0) && !(aux->tp_status & TP_STATUS_VLAN_VALID))
				continue;
			printf("iov_len:%d, len:%d\n", iov.iov_len, len);
			int i = 0;
			for(i = 0; i<cmsg->cmsg_len;i++)
				printf("%02hhx ",ptrbuf[i]);
			printf("\n");
			
			ret += 4;
		}

	}

	//len = sizeof(sl);
	//ret = recvfrom(sock, pack, sizeof(*pack), 0, (struct sockaddr *)&sl, &len);
	if(ret == -1) {
		if(errno == EINTR)	/* We have a timeout */
			return 0;
		perror("recvfrom");
		exit(1);
	}
	if((pack->llc.ctrl & TEST_CMD) != TEST_CMD) {
		fprintf(stderr, "got unexpected packet\n");
		dump_packet(pack);
		/* continue anyway ! exit(1);*/
	}
	ret = ntohs(pack->eth_hdr.ether_type);
	if(debug_flag)
		printf("received TEST packet (%d bytes) from %s\n", ret, mac2str(pack->eth_hdr.ether_shost));

	return ret;
}

