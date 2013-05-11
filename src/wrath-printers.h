#include <stdio.h>
#include <libnet.h>

void wrath_attack_packet_stats(struct libnet_ipv4_hdr *iphdr, struct libnet_tcp_hdr *tcphdr, int tcp_sum, int payload_size, FILE *logfp) {
	//out = logfp == 0 ? stdout : log_buffer;

	fprintf(logfp, "With ... ");
	fprintf(logfp, "%s:%hu -->", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	fprintf(logfp, " %s:%hu\n", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	fprintf(logfp, "Seq: %u ", ntohl(tcphdr->th_ack));
	fprintf(logfp, "Ack: %u\n", ntohl(tcphdr->th_seq));
	fprintf(logfp, "Control: 0x%04x\n", tcp_sum);
	fprintf(logfp, "%d bytes of data\n", payload_size);
	fprintf(logfp, "----------------\n");
}

void wrath_capture_stats(struct libnet_ipv4_hdr *iphdr, struct libnet_tcp_hdr *tcphdr, FILE *logfp) {
	/*
	unsigned char log_buffer[150];
	unsigned char *out;
	out = logfd == 0 ? stdout : log_buffer;
	*/

	fprintf(logfp, "Hijacking ... ");
	fprintf(logfp, "%s:%hu -->", inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
	fprintf(logfp, " %s:%hu\n", inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
	fprintf(logfp, "Seq: %u ", ntohl(tcphdr->th_ack));
	fprintf(logfp, "Ack: %u\n", ntohl(tcphdr->th_ack));
	fprintf(logfp, "Control: 0x%04x\n", (tcphdr->th_flags));
	fprintf(logfp, "\n");
}
