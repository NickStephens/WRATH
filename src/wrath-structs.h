#include <libnet.h>

/*
 structure for argument evalutation
*/
struct arg_values {
	char *interface; // listening interface
	char *input_file; // application-level encoding
	int tcp_urg; // tcp-flags to set (booleans)
	int tcp_ack;
	int tcp_psh;
	int tcp_rst;
	int tcp_syn;
	int tcp_fin;
	char *operation; // application-level operation
	char *command; // application-level command
	char *filter; // bpf
	int count; // how many packets to victimize
};

/* structure for packaging useful information */
struct lcp_package {
	libnet_t *libnet_handle; // libnet context
	struct arg_values *cline_args; // command-line arguments
	u_char *packet;	// packet forgery memory
};
