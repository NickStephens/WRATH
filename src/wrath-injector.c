#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct arg_value *cline_args = (struct arg_value *) args;
	printf("[DEBUG] packet captured!\n");
}
