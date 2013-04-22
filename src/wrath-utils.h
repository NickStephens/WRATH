#include <stdio.h>
#include <stdlib.h>

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
