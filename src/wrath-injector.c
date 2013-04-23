#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"
#include "wrath-builders.h"
#include "wrath-utils.h"

void wrath_build_and_launch(u_char *, const u_char *, u_char *);

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;
	char *app_cmd;
	
	/* test for input file:
		if an input file exists, assume it contains all encoding information.
		read the file's data onto the heap.
		present the pointer to wrath_build.
	
	   if an input file does not exist see if an operation does.
	   
	   if an operation does not exist only pass null pointer.
	*/
	if (strcmp(cline_args->input_file, "\0") != 0) { // If an input file has been specified
		int app_fd, length;
		app_fd = open(cline_args->input_file, O_RDONLY, 0);
		if ((length = file_size(app_fd)) == -1)
			fatal_error("getting file size");
		unsigned char *ptr = (unsigned char *) safe_malloc(length);
		read(app_fd, ptr, length);
		app_cmd = ptr;
	} else if (strcmp(cline_args->command, "\0") != 0) // If a command has been specified but not an input file
		app_cmd = cline_args->command;

	/* looks to see if an operation is set.
	 * when operations are set packets are only launched in 
	 * response to packets which share their operations 
	 * protocol */
	char *op = cline_args->operation;
	if (strcmp(op, "http") == 0 || strcmp(op, "HTTP") == 0 ) { // HTTP response
		char *app_cmd_con = (char *) safe_malloc(sizeof(app_cmd));
		wrath_char_encode(app_cmd, app_cmd_con);
		if (strstr(packet + LIBNET_ETH_H + (2 * LIBNET_TCP_H) , "HTTP") != NULL) {
			printf("HTTP Packet sniffed\n");
			wrath_tcp_belly_build_and_launch(args, packet, NULL, TH_ACK, 0);	
			wrath_tcp_belly_build_and_launch(args, packet, app_cmd_con, (TH_ACK + TH_PUSH), 1);
		}
		free(app_cmd_con);
	// else if (strcmp(op, "ftp") == 0 || strcmp(op, "FTP") == 0)
	} else if (strcmp(op, "\0") == 0 || strcmp (op, "tcp") == 0 || strcmp(op, "TCP") == 0) // TCP is default
			wrath_tcp_raw_build_and_launch(args, packet);

	free(app_cmd);
}
