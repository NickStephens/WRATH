/* contains function prototypes for
 * wrath building functions */

/* builds a a tcp header with nothing resting above it
 * acknowledges TCP flags from the command line */
void wrath_tcp_raw_build_and_launch(u_char *, const u_char *, FILE *);

/* builds a more customizable TCP packet */
void wrath_tcp_custom_build_and_launch(libnet_t *, struct in_addr, struct in_addr,
	short, short, long, long, int);

/* builds a tcp header to support an upper level protocol 
 * above it, does not acknowledge TCP falgs from teh 
 * command line */
void wrath_tcp_belly_build_and_launch(u_char *, const u_char *, unsigned char *, unsigned int);
