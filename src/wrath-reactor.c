#include <pcap.h>

void wrath_inject(u_char *, const struct pcap_pkthdr *, const u_char *);
// will need to cast the pointer to u_char. (struct arg_vals *) args

// places wrath in the position to capture the victims packets
void wrath_position(struct arg_val *cline_args) {
	struct pcap_pkthdr cap_header;
	const u_char *packet, *pkt_date;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	pcap_t *pcap_handle;
	
	if (cline_args->interface == NULL) {
		if (device = pcap_lookupdev(errbuf) == NULL)	
			//pcap_perror
	} else
		device = cline_args->interface;

	printf("Victimizing on %s", device);	

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf); //snaplen is small because we only need the headers
	/* if(pcap_handle == NULL)
		pcap_perror
	*/

	// parse/compile bpf (if filter is null, skip this step)
	if (cline_args->filter != NULL) {
		struct bpf_program *fp;
		pcap_compile(pcap_handle, fp, cline_args->filter, 1, PCAP_NETMASK_UNKNOWN)
		/* if(pcap_compile(pcap_handle, fp, cline_args->filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
			pcap_perror(pcap_handle);
		*/
		pcap_setfilter(pcap_handle, fp);
	}

	int cap_amount = -1;
	if (cline_args->count != NULL)
		cap_amount = cline_args->count;

	pcap_loop(pcap_handle, cap_amount, wrath_inject, cline_args);
}
