#include <pcap.h>
#include <stdlib.h>
#include "wrath-structs.h"

void wrath_inject(u_char *, const struct pcap_pkthdr *, const u_char *);
// will need to cast the pointer to u_char. (struct arg_vals *) args

// places wrath in the position to capture the victims packets
void wrath_position(struct arg_values *cline_args) {
	struct pcap_pkthdr cap_header;
	const u_char *packet, *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	pcap_t *pcap_handle;
	
	if (strcmp(cline_args->interface, "\0") == 0) { // if interface is not set
		device = pcap_lookupdev(errbuf);
		if(device == NULL) {
			fprintf(stderr, "ERROR FETCHING INTERFACE: %s %s\n", errbuf, "(are you root?)");
			exit(1);
		}
	} else { // if interface is set
		device = cline_args->interface;
	}

	printf("Watching victims on %s\n", device);	

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf); //snaplen is small (4kb) because we only need the headers

	// parse/compile bpf (if filter is null, skip this step)
	if (cline_args->filter != NULL) { // if filter is set
		struct bpf_program *fp;
		if((pcap_compile(pcap_handle, fp, cline_args->filter, 1, PCAP_NETMASK_UNKNOWN)) == -1)
			pcap_perror(pcap_handle, "ERROR compiling filter");
		pcap_setfilter(pcap_handle, fp);
	}

	int cap_amount = -1;
	if (cline_args->count != -1) // if count is set
		cap_amount = cline_args->count;

	pcap_loop(pcap_handle, cap_amount, wrath_inject, (u_char *) cline_args);

	pcap_close(pcap_handle);
}
