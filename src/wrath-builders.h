/* contains function prototypes for
 * wrath building functions */

/* builds a a tcp header with nothing resting above it
 * acknowledges TCP flags from the command line */
void wrath_tcp_raw_build_and_launch(u_char *, const u_char *);

/* builds a tcp header to support an upper level protocol 
 * above it, does not acknowledge TCP falgs from teh 
 * command line */
void wrath_tcp_belly_build_and_launch(u_char *, const u_char *, unsigned char *, unsigned int, int);
