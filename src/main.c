#include <stdlib.h>
#include "wrath.h"

int main(int argc, char *argv[]) {

	struct arg_values *user_values;
	user_values = (struct arg_values *) malloc(sizeof (struct arg_values));
	arg_eval(argc, argv, user_values);	

	printf("Filter: %s\n", user_values->filter);
	printf("Number: %d\n", user_values->count);
	printf("Operation: %s\n", user_values->operation);
	printf("Command: %s\n", user_values->command);
	printf("Interface: %s\n", user_values->interface);
	printf("Input File: %s\n", user_values->input_file);

	printf("RST: 0x%02x\n", user_values->tcp_rst);
	printf("URG: 0x%02x\n", user_values->tcp_urg);
	printf("PSH: 0x%02x\n", user_values->tcp_psh);
	printf("FIN: 0x%02x\n", user_values->tcp_fin);
	printf("SYN: 0x%02x\n", user_values->tcp_syn);
	printf("ACK: 0x%02x\n", user_values->tcp_ack);

	//wrath_observe(user_values);

	free(user_values);
}
