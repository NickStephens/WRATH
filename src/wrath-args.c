#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wrath-structs.h"

#define USAGE "usage: wrath [options] [operation] [filter] \n \
	       example: wrath -i eth0 -f spook.html http \"OK 200\" \"src host 10.0.0.7\" \n \
	       \n \
	       -i interface \n \
	       -f input file \n \
	       -tflag [-tS, -tA, -tF, -tP, -tU, -tR] \n"       

void usage_error(int, int, char *);
void initialize(struct arg_values *);

/**
 * Scans the command-line arguments and 
 * and places them into a arg_values struct
 * @param int, the argument count
 * @param char **, the array of command-line
 * arguments
 * @param struct arg_values *, the struct to 
 * store results in
 */
void arg_eval(int argc, char *argv[], struct arg_values *values) {
	char *opt;
	int i;
	initialize(values);
	for (i = 1; i < argc; i++) { // skipping first argument, program name
		opt = argv[i];
		if (strcmp(opt, "-i") == 0) { // interface
			char *interface = argv[++i];
			usage_error(i, argc, "missing parameter for -i");
			values->interface = interface;
		}
		else if (strcmp(opt, "-f") == 0) { // input file
			char *file = argv[++i];
			usage_error(i, argc, "missing parameter for -f");
			values->input_file = file;
		}
		else if (strcmp(opt, "-o") == 0) { // explicitly specify operation
			char *operation= argv[++i];
			usage_error(i, argc, "missing parameter for -o");
			values->operation = operation;
		}
		else if (strcmp(opt, "-c") == 0) { // explicitly specify command (may later be bundled into operation
			char *command = argv[++i];
			usage_error(i, argc, "missing parameter for -c");
			values->command = command;
		}
		else if (strcmp(opt, "-tU") == 0) { // URG
			values->tcp_urg = 1;
		}
		else if (strcmp(opt, "-tA") == 0) { // ACK
			values->tcp_ack = 0;   // mark ack flag off
		}
		else if (strcmp(opt, "-tP") == 0) { // PSH
			values->tcp_psh = 1;
		}
		else if (strcmp(opt, "-tR") == 0) { // RST
			values->tcp_rst = 1;
		}
		else if (strcmp(opt, "-tS") == 0) { // SYN
			values->tcp_syn = 1;
		}
		else if (strcmp(opt, "-tF") == 0) { // FIN
			values->tcp_fin = 1;
		}
		else if (strcmp(opt, "-n") == 0) { // count, the amount of packets for interface to victimize
			char *capture_amount = argv[++i];
			usage_error(i, argc, "missing paramter for -n");
			values->count = atoi(capture_amount);
		} 
		else if (i == (argc - 1)) { // if it's the final argument and not an option, it's a bpf
				if (*opt == '-') // if it's decorated like an option
					usage_error(0,0,"unrecognized option");
				values->filter = opt;
		} else if (i == (argc - 3)) { // if it's the 3rd from last argument and not an options its an operation and command
				if (*opt == '-') // if it's decorated like an option
					usage_error(0,0,"unrecognized option");
				values->operation = opt;
				values->command = argv[++i];
		}
		else
			usage_error(0, 0, "unrecognized option");
	}
}

/**
 * intializes an arg_values struct by setting
 * all its members to an appropriate default 
 * setting.
 * @param struct arg_values *, structure to be initialized
 */
void initialize(struct arg_values *values) {
	values->operation = "\0";
	values->command = "\0";
	values->filter = "\0";
	values->interface = "\0";
	values->input_file = "\0";
	values->tcp_urg = 0;	
	values->tcp_ack = 1;	// by default ack is set
	values->tcp_psh = 0;	
	values->tcp_rst = 0;	
	values->tcp_syn = 0;	
	values->tcp_fin = 0;	
	values->count = -1;
}

void nothing(struct arg_values *values) {
	/*
	values->operation = "\0";
	values->command = "\0";
	values->filter = "\0";
	values->interface = "\0";
	values->input_file = "\0";
	*/
	values->tcp_urg = 0;	
	values->tcp_ack = 1;	// by default ack is set
	values->tcp_psh = 0;	
	//values->tcp_rst = 0;	
	values->tcp_syn = 0;	
	values->tcp_fin = 0;	
	values->count = 0;
}

/**
 * terminates execution and prints an error
 * to catch bad command-line arguments.
 * @param int, current scanning position
 * @param int, argument count
 * @param char *, a string with an error message
 */
void usage_error(int pos, int argc, char *mesg) {
	if (pos >= argc) {	
		printf("%s\n", mesg);
		printf("%s", USAGE);
		exit(EXIT_FAILURE);
	}
}
