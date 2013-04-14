#include <libnet.h>

void inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	arg_val *cline_args = (struct arg_val *) args;
