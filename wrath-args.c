#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct arg_kv {
	char *key;
	char *value;
};

struct key_table_cell {
	char *flag;
	char *key;
};

#define BYTES_OF_ARGUMENTS 32

const struct key_table_cell key_table[] = { {"-i", "interface"},  // listening interface
					    {"-f", "input-file"}, // file with application-level encoding
					    {"\0", "\0"},	  // no op, end of table marker
					  };

main() {
	int i;
	char *key;
	for (i=0; strcmp((key = key_table[i].key), "\0") != 0; i++)
		printf("%s\n", key);	
}

/*
struct arg_kv find_key(char *opt){
	int j = 0;
	struct key_table_cell cell = key_table[j];
	while(strcmp( cell.key, "\0") != 0) {
		if (strcmp(opt, cell.key) == 0) {
			struct arg_kv ret;
			ret.key = cell.key;
			ret.value 
			
					
}
*/
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
		while(strcmp( cell.key, "\0") != 0) {
			if (strcmp(opt, cell.key) == 0) {
				struct arg_kv ret;
				ret.key = cell.key;
				if (++i < argc) {
					ret.value = argv[i];
					pairs[arg_cnt++];
					break;
				} else
					usage_error(strcat(strcat(strcat("missing ",cell.key)," for option "),cell.flag));
			}
			j++;
		}
		if (strcmp( cell.key, "\0") == 0)
			usage_error(strcat("unrecognized option ",opt));
	}
/* Attempt number one
	struct arg_kv pairs[] = malloc(BYTES_OF_ARGUMENTS);
	
	char *opt;
	int size = 0;
	int i;
	for (i = 1; i < argc; i++) { // i set to one to skip name of program 
		opt = argv[i];	
		struct key_table_cell current_tc;
		struct arg_kv *current_arg = malloc(8);
		int j;
		for (j = 0; strcmp((current_tc = key_table_cell[j]).flag, "\0") != 0; j++) {
			if (strcmp(current_tc.flag, opt) == 0) {
				*current_arg.key = current_tc.key;
				*current_arg.value = argv[++i]; 
			}
		}
		pairs[size++] = current_arg;
	}
	
	return pairs; */
}	

void usage_error(char *mesg) {
	printf("error\n");
	exit(EXIT_FAILURE);
}
