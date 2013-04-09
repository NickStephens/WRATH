/*
 structure for argument evalutation
*/

// argument key-value pair
struct arg_kv {
	char *key;
	char *value;
};

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
};
