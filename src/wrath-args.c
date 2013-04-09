#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "wrath-structs.h"

#define USAGE "usage: wrath [options] [operation] [filter] \n \
	       example: wrath -i eth0 -f spook.html http \"src host 78.23.87.99\" \n \
	       \n \
	       -i interface \n \
	       -f input file \n \
	       -tflag [-tS, -tA, -tF, -tP, -tU, -tR] \n "        
	

struct key_table_cell {
	char *flag;
	char *key;
};

const struct key_table_cell key_table[] = { {"-i", "interface"},  // listening interface
					    {"-f", "input-file"}, // file with application-level encoding
					    {"-tflag", "tcp flag"}, // the tcp flag to set
					    {"\0", "\0"},	  // no op, end of table marker
					  };

// returns a pointer to an array of arg-kv structs
// the result will have to be cast, like pairs = (arg-kv *) arg-eval(argv);
void arg_eval(int argc, char *argv[], struct arg_kv pairs[]) {
	char *opt;
	int arg_cnt = 0;
	int i;
	for (i = 1; i < argc; i++) {
		opt = argv[i];
		int j = 0;
		struct key_table_cell cell = key_table[j];
		while(strcmp( cell.flag, "\0") != 0) {
			if (strcmp(opt, cell.flag) == 0) {
				struct arg_kv ret;
				ret.key = cell.key;
				if (++i < argc) {
					ret.value = argv[i];
					pairs[arg_cnt++];
					break;
				} else 
					usage_error("missing parameter");
			}
			cell = key_table[++j];
		}
		if (strcmp( cell.key, "\0") == 0)
			usage_error("unrecognized option");
//(strcat("unrecognized option ",opt))
//(strcat(strcat(strcat("missing ",cell.key)," for option "),cell.flag))
	}
}

void usage_error(char *mesg) {
	printf("%s\n", mesg);
	printf("%s", USAGE);
	exit(EXIT_FAILURE);
}
