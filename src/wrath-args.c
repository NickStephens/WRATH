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

const struct key_table_cell key_table[] = { 
	{"-i", "interface"}, // listening interface
	{"-f", "input-file"}, // file with application-level encoding
	{"-tflag", "tcp flag"}, // the tcp flag to set
					  };

struct arg_kv *get_additional(char *, char **, int);
void usage_error(char *);

// modifies the pairs array
void arg_eval(int argc, char *argv[], struct arg_kv **pairs) {
	char *opt;
	int i;
	/* for later
	if (argc < 2)
		usage_error("missing parameters");
	filter = argv[argc - 1];
	operation = argv[argc - 2];
	*/
	//for(i = 1; i < argc; i++) { // this will have to change to (argc - 2) when operation and filter are used	
		i = 1;
		opt = argv[i];
		*pairs = get_additional(opt, argv, i++);
		pairs++;	
	//}

}

struct arg_kv *get_additional(char *scanned, char *argv[], int pos) {
	int j;
	for (j = 0; j < (sizeof key_table / sizeof (struct arg_kv)); j++) {
		if (strcmp(scanned, key_table[j].flag) == 0) {
			struct arg_kv *ret;
			ret = (struct arg_kv *) malloc(sizeof (struct arg_kv));
			ret->key = key_table[j].key;
			ret->value = argv[pos+1];
			return ret;
		}
	}
}

void usage_error(char *mesg) {
	printf("%s\n", mesg);
	printf("%s", USAGE);
	exit(EXIT_FAILURE);
}
