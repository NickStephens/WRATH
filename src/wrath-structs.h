#include <libnet.h>

/*
 structure for argument evalutation
*/
struct arg_values {
	char interface[20]; // listening interface
	char input_file[100]; // application-level encoding
	int tcp_urg; // tcp-flags to set (booleans)
	int tcp_ack;
	int tcp_psh;
	int tcp_rst;
	int tcp_syn;
	int tcp_fin;
	char operation[20]; // application-level operation
	char command[100]; // application-level command
	char filter[300]; // bpf
	char logfile[100]; // logfile
	int count; // how many packets to victimize
	int sleep_time; // amount of millisecond to wait in between packet injection
};

/* structure for packaging useful information */
struct lcp_package {
	libnet_t *libnet_handle; // libnet context
	struct arg_values *cline_args; // command-line arguments
	char *payload; // libnet payload attachment
	FILE *logfile; // logfile pointer
};

/* injection information */
struct inject_package {
	const unsigned char *stream; // stream of bytes representing inject data
	int length; // length of the stream (used for libnet packet crafting in TCP header)
};

struct packet_sizes {
	unsigned int total_len; // the length of the entire packet
	unsigned int tcp_header_len; // the length of the tcp header
	unsigned int app_header_len; // the length of the application header
};
