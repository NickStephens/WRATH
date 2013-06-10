#include <libnet.h>

/* Launches an HTTP Response
 * @param data_pass, contains the libnet_handle among other things
 * @param packet, the packet captured by pcap
 * @param payload, the payload of the packet to inject
 * @param logfd
 */
void wrath_launch_http_response(u_char *, const u_char *, u_char *, int, FILE *);

/* Launches a generic attack packet
 * @params (same as wrath_launch_http_response)
 */
void wrath_launch_generic(u_char *, const u_char *, u_char *, int, FILE *);
