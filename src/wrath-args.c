#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wrath-structs.h"

void usage();

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

	int cnt = 0;

	if (argc < 2)
		usage();

	memset(values, 0x00, (sizeof (struct arg_values)));
	while((i = getopt(argc, argv, "hn:o:c:i:f:t:a:l:")) != -1) {
		switch(i) {
			case 'h': usage();
			case 'l': strcpy(values->logfile, optarg); cnt = cnt+2; break;
			case 'n': values->count = atoi(optarg); cnt = cnt+2; break;
			case 'o': strcpy(values->operation, optarg); cnt = cnt+2; break;
			case 'c': strcpy(values->command, optarg); cnt = cnt+2; break;
			case 'i': strcpy(values->interface, optarg); cnt = cnt+2; break;
			case 'a': strcpy(values->input_file, optarg); cnt = cnt+2; break;
			case 'f': strcpy(values->filter, optarg); cnt = cnt+2; break;
			case 't': c = optarg[0]; cnt++; switch(c) {
				case 'U': values->tcp_urg = 0x20; break;
				case 'A': values->tcp_ack = 0x10; break;
				case 'P': values->tcp_psh = 0x08; break;
				case 'R': values->tcp_rst = 0x04; break;
				case 'S': values->tcp_syn = 0x02; break;
				case 'F': values->tcp_fin = 0x01; break;
				default: usage();
				} break;
			default: usage();
		}
	}
	if (cnt < argc - 1)
		strcpy(values->filter, argv[++cnt]);
}

/**
 * terminates execution and prints an error
 * to catch bad command-line arguments.
 * @param int, current scanning position
 * @param int, argument count
 * @param char *, a string with an error message
 */
void usage() {
	printf("usage: wrath [options] filter\n");
	printf("example: wrath -o http-resp -a appheaders/takeover \"src host 10.0.0.7\"\n"); 
	printf("\n");
	printf("\t-h\tdisplay this help\n");
	printf("\t-n\tnumber of packets to intercept\n");
	printf("\t-o\texplicitly supply operation\n");
	printf("\t-c\texplicitly supply command\n");
	printf("\t-f\texplicitly supply filter\n");
	printf("\t-i\tinterface\n");
	printf("\t-a\tattach input file as payload\n");
	printf("\t-l\tlog output to the file specified\n");
	printf("\t-tU\tmark tcp URG flag\n"); // consider taking these out
	printf("\t-tA\tmark tcp ACK flag\n"); // and only documenting them
	printf("\t-tP\tmark tcp PUSH flag\n"); // in the man page.
	printf("\t-tR\tmark tcp RST flag\n");
	printf("\t-tS\tmark tcp SYN flag\n");
	printf("\t-tF\tmark tcp FIN flag\n");
	printf("\n");
	printf("\tOPERATIONS:\n");
	printf("\t* http-resp\t:: HTTP Response\n");
	printf("\t* http-rqst\t:: HTTP Request\n");
	printf("\t* tcp\t\t:: bare tcp\n");
	printf("\t* no-string\t:: any packet with application data\n");
	printf("\t* <match>\t:: any packet whose application data contains $match\n");
	exit(0);
}
