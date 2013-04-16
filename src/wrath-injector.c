#include <libnet.h>
#include <pcap.h>
#include "wrath-structs.h"

void wrath_inject(u_char *args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
	struct lcp_package *package = (struct lcp_package *) args;
	libnet_t *libnet_handle = package->libnet_handle;
	struct arg_values *cline_args = package->cline_args;

	struct libnet_ipv4_hdr *iphdr;
	struct libnet_tcp_hdr *tcphdr;

	iphdr = (struct libnet_ipv4_hdr *) (packet + LIBNET_ETH_H);
	tcphdr = (struct libnet_tcp_hdr *) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	printf("%s -->", inet_ntoa(iphdr->ip_src));
	printf(" %s\n", inet_ntoa(iphdr->ip_dst));

	/* build application layer -- this order is only a libnet requirement, so maybe not */

	/* libnet_build_tcp */
	/* libnet_build_tcp(LIBNET_TCP_H, */
	
	
	libnet_build_ipv4(LIBNET_TCP_H, // length
	IPTOS_LOWDELAY,			// type of service
	libnet_get_prand(LIBNET_PRu16), // IP ID (serial)
	0,				// fragmentation
	128,				// TTL should be high to avoid being dropped in transit to a server
	IPPROTO_TCP,			// upper-level protocol
	0,				// checksum: 0 = libnet auto-fill
	*((u_long *)&(iphdr->ip_dst)),  // source (pretend to be desitination)
	*((u_long *)&(iphdr->ip_src)),  // destination (pretend to be source)
	NULL,				// optional payload
	0,				// payload length
	libnet_handle,			// pointer libnet context
	0);				// ptag: 0 = build a new header	

	printf("shooting off dummy response packet\n");
	libnet_write(libnet_handle);
	printf("shot\n");
}
