#include <libnet.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
	int i_selected;
	char *interface;
	
	// hardcoded interface selection
	if (argc > 2) {
		interface = argv[2];
	}
		
	char error[LIBNET_ERRBUF_SIZE];

	printf("Assigning libnet to interface: %s", interface);
	libnet_init( 1, interface, error);
}
