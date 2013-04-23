#include <stdio.h>
#include <stdlib.h>

/* A set of functions used to craft HTTP Headers to 
 * be injected into the network by wrath */

/* host file to network file
 * @param file name to be converted
 * @param pointer of location to place file
 * @param size of file in bytes */
char *wrath_htonf(char *name, unsigned char *ptr, int file_length) {
		FILE fp*;	
		int i, current_four_chars;

		fp = fopen(name, "r");

unsigned char *wrath_chars_to_int(unsigned char one, unsigned char two, unsigned char three, unsigned char four) {
		unsigned char network_order[4];

		network_order[0] = four;
		network_order[1] = three;
		network_order[2] = two;
		network_order[4] = one;

		return network_order;
}
