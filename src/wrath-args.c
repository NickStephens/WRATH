#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wrath-structs.h"

#define USAGE "usage: wrath [options] [operation] [filter] \n \
	       example: wrath -i eth0 -f spook.html http \"src host 78.23.87.99\" \n \
	       \n \
	       -i interface \n \
	       -f input file \n \
	       -tflag [-tS, -tA, -tF, -tP, -tU, -tR] \n"        

void usage_error(int, int, char *);
void initialize(struct arg_values *);

// modifies the pairs array
void arg_eval(int argc, char *argv[], struct arg_values *values) {
	char *opt;
	int i;
	initialize(values);
	for (i = 1; i < argc; i++) { // skipping first argument, program name
		opt = argv[i];
		if (strcmp(opt, "-i") == 0) {
			char *interface = argv[++i];
			usage_error(i, argc, "missing parameter for -i");
			values->interface = interface;
		}
		else if (strcmp(opt, "-f") == 0) {
			char *file = argv[++i];
			usage_error(i, argc, "missing parameter for -f");
			values->input_file = file;
		}
		else if (strcmp(opt, "-tU") == 0) {
			values->tcp_urg = 1;
		}
		else if (strcmp(opt, "-tA") == 0) {
			values->tcp_ack = 0;   // mark ack flag off
		}
		else if (strcmp(opt, "-tP") == 0) {
			values->tcp_psh = 1;
		}
		else if (strcmp(opt, "-tR") == 0) {
			values->tcp_rst = 1;
		}
		else if (strcmp(opt, "-tS") == 0) {
			values->tcp_syn = 1;
		}
		else if (strcmp(opt, "-tF") == 0) {
			values->tcp_fin = 1;
		}
		else {
			if (i == (argc - 1)) // if it's the final argument and not an option, it's a bpf
				values->filter = opt;
			if (i == (argc - 3)) { // an operation
				values->operation = opt;
				values->command = argv[++i];
			}
		}
	}
}

void initialize(struct arg_values *values) {
	values->tcp_urg = 0;	
	values->tcp_ack = 1;	// by default ack is set
	values->tcp_psh = 0;	
	values->tcp_rst = 0;	
	values->tcp_syn = 0;	
	values->tcp_fin = 0;	
}

void usage_error(int pos, int argc, char *mesg) {
	if (pos >= argc) {	
		printf("%s\n", mesg);
		printf("%s", USAGE);
		exit(EXIT_FAILURE);
	}
}
