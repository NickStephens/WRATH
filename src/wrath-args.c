#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wrath-structs.h"

#define PARAMETER_MISSING "missing parameter for "
#define UNRECOGNIZED_OPTION "unrecognized option "

#define USAGE "usage: wrath [options] [operation] [filter] \n \
	       example: wrath -i eth0 -f appheaders/redirect http \"src host 10.0.0.7\" \n \
	       \n \
	       	-h 	display this help \n \
	       	-n	number of packets to intercept \n \
	       	-o	explicitly supply operation \n \
	       	-c 	explicitly supply command \n \
	       	-i 	interface \n \
	       	-f 	input file \n \
	       	-tU 	mark tcp URG flag \n \
	       	-tA 	unmark tcp ACK flag \n \
		-tP 	mark tcp PSH flag \n \
		-tR 	mark tcp RST flag \n \
		-tS 	mark tcp SYN flag \n \
		-tF 	mark tcp FIN flag \n"

void usage_error(int, int, char *, char *);
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
	int i, c;
	//	initialize(values);
	memset(values, 0x00, (sizeof (struct arg_values)));
	while((i = getopt(argc, argv, "hn:o:c:i:f:t")) != -1) {
		switch(i) {
			case 'h': usage_error(0,0,"",""); break;
			case 'n': values->count = atoi(optarg); break;
			case 'o': strcpy(values->operation, optarg); break;
			case 'c': strcpy(values->command, optarg); break;
			case 'i': strcpy(values->interface, optarg); break;
			case 'f': strcpy(values->input_file, optarg); break;
			case 't': c = getopt(argc,argv,"UPFRSA"); /* switch(c) {
				case 'U': values->tcp_urg = 0x20;
				case 'A': values->tcp_urg = 0x10;
				case 'P': values->tcp_urg = 0x08;
				case 'R': values->tcp_urg = 0x04;
				case 'S': values->tcp_urg = 0x02;
				case 'F': values->tcp_urg = 0x01;
				} */
				//printf("%d, %s\n", c);
		}
	}
}

/**
 * intializes an arg_values struct by setting
 * all its members to an appropriate default 
 * setting.
 * @param struct arg_values *, structure to be initialized
 */
void initialize(struct arg_values *values) {
	/*
	values->operation = "\0";
	values->command = "\0";
	values->filter = "\0";
	values->interface = "\0";
	values->input_file = "\0";
	values->tcp_urg = 0x00;	
	values->tcp_ack = 0x00;
	values->tcp_psh = 0x00;	
	values->tcp_rst = 0x00;	
	values->tcp_syn = 0x00;	
	values->tcp_fin = 0x00;	
	values->count = -1;
	values->sleep_time = -1;
	*/
}

/**
 * terminates execution and prints an error
 * to catch bad command-line arguments.
 * @param int, current scanning position
 * @param int, argument count
 * @param char *, a string with an error message
 */
void usage_error(int pos, int argc, char *mesg, char *opt) {
	if (pos >= argc) {	
		fprintf(stderr, "%s %s\n", mesg, opt);
		fprintf(stderr, "%s", USAGE);
		exit(EXIT_FAILURE);
	}
}
