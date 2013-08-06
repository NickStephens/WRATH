#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* many of these functions are heavily influenced by Jon Erickson's design in his
   book "Hacking: The Art of Exploitation" */

/* prints error message and exits */
void fatal_error(char *err_mesg) {
	fprintf(stderr, "[ERROR] %s\n", err_mesg);
	exit(1);
}

/* attempts to allocate space on the heap through malloc.
 * if an error occurs, the program terminates. */
void *safe_malloc(int size) {
	void *ptr;
	if ((ptr = malloc(size)) == NULL)	
		fatal_error("try to allocate memory on heap");
	return ptr;
}

/* gets the size of a file in bytes given a file descriptor. */
int file_size(int fd) {
	struct stat sts;

	if (fstat(fd, &sts) == -1)
		return -1;
	return (int) sts.st_size;	
}

void shiftl(char *str) {
	char *temp;
	while (*str != '\0') {
		temp = str;
		str++;
		*temp = *str;
	}
}

/* encodes \n and \r to their correct hexadecial values 
 * within a string 
 * @param the string to convert
 * @param the string to place the conversions into */
char *wrath_char_encode(char *str, char *new_str) {
	char *top;
	new_str = strcpy(new_str, str);
	top = new_str;	
	while (*new_str) {
		if (*new_str == '\\') {
			++new_str;
			if (*new_str == 'r')
				*new_str = (char) 0x0d;
			shiftl(--new_str);
		}
		new_str++;
	}
	return (new_str = top);
}
