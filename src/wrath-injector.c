#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct arg_value *cline_args = (struct arg_value *) args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("%s -->", inet_ntoa(iphdr->ip_src));
	printf(" %s\n", inet_ntoa(iphdr->ip_dst));
	
	/*
	libnet_build_ip(LIBNET_TCP_H,
	IPTOS_LOWDELAY,
	libnet_get_prand(LIBNET_PRU16),
	0,
	128,				// TTL
	IPPROTO_TCP,
	*((u_long *)&(iphdr->ip_dst)),
	*((u_long *)&(iphdr->ip_src)),
	NULL,				// Payload
	0,				// Payload Length
	//libnet data
	*/
}
