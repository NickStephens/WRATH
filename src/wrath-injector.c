#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-builders.h"
#include "wrath-utils.h"
#include "wrath-applevel.h"

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
	FILE *out = package->logfile == 0 ? stdout : package->logfile;

	/* looks to see if an operation is set.
	 * when operations are set packets are only launched in 
	 * response to packets which share their operations 
	 * protocol */
	struct packet_sizes pk_size;
	wrath_calculate_sizes(packet, &pk_size);
	const u_char *app_begin = packet + LIBNET_ETH_H + LIBNET_TCP_H + pk_size.tcp_header_len;

	char *op = cline_args->operation;
	if (strcmp(op, "http-resp") == 0 || strcmp(op, "HTTP-RESP") == 0 || strcmp(op, "http-response") == 0 || strcmp(op, "HTTP-RESPONSE") == 0) { // HTTP response
		if (strstr(app_begin, "HTTP") != NULL) {
			fprintf(out , "HTTP Packet sniffed\n", 20);
			wrath_launch_http_response(args, packet, package->payload, out);
		}
	} else if (strcmp(op, "http-rqst") == 0 || strcmp(op, "HTTP-RQST") == 0 || strcmp(op, "http-request") == 0 || strcmp(op, "HTTP-REQUEST") == 0) { // HTTP Request
		if (strstr(app_begin, "HTTP") != NULL) {
			fprintf(out , "HTTP Packet sniffed\n", 20);
			wrath_launch_generic(args, packet, package->payload, out);
		}
	} else if (strcmp(op, "irc") == 0 || strcmp(op, "IRC") == 0) { 
		if (strstr(app_begin, "PING") == NULL && strstr(app_begin, "PONG") == NULL && pk_size.app_header_len > 0) { // Ignore server client checkups
			fprintf(out, "IRC Packet sniffed\n");
			wrath_launch_generic(args, packet, package->payload, out);
		}
	} else if (strcmp(op, "no-string") == 0) { // responds to any packet which has an application header
		if (pk_size.app_header_len > 0)
			wrath_launch_generic(args, packet, package->payload, out);
	} else if (strcmp(op, "\0") == 0 || strcmp (op, "tcp") == 0 || strcmp(op, "TCP") == 0) { // TCP is default
			wrath_tcp_raw_build_and_launch(args, packet, out);
	} else if (strcmp(op, "\0") != 0) { // generic case
		if (strstr(app_begin, op) != NULL) {
			fprintf(out, "%s Packet sniffed\n", op);
			wrath_launch_generic(args, packet, package->payload, out);	
		}
	}
}
