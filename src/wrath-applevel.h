#include <stdio.h>

/* takes a character stream from a file and converts the
 * the contents into network byte ordering 
 * host-to-network-header */
char *wrath_htonh(const u_char *stream);

/* takes all newlines in an http header and converts
 * them to carriage-returns */
char *wrath_http_nltocr(const u_char *stream);
