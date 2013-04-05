#include <libnet.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
	char error[LIBNET_ERRBUF_SIZE];

	libnet_init( 1, "enp0s1", error);
}
