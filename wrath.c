#include <libnet.h>
#include <pcap.h>
//#include "wrath-args.h" functions which return an array of key-value pairs given argv[]
//#include "http-injector.h" functions which parse HTTP commands and insert it into the proper packet header and payload
//#include "ip-tcp-craft.h" functions automating the tedious low-level packet crafting process

int main(int argc, char *argv[]) {
	/* Options WRATH should have
		-i select interface to sniff and forge on
		-f input file for payload
	
		operations:
		http
		ftp
		custom (allows the user to send a packet matching the encoding of the selected file)
	*/
	char error[LIBNET_ERRBUF_SIZE];

	/* Algorithm
		first sniff a packet that matches the berkeley packet filter syntax (the expression will be delivered via wrath-argj)
		NOTE: The packet's origin address is the address representing the victim machine.
	
		Information will be inferred from the sniffed packet used to construct low-level headers (IP, TCP (Mayber ETHER if they share a subnet))

		The sniffed packets SEQ,ACK, and packet length numbers are critical. With these we will forge a packet destined for the source
		pretending to be the packet's original desitination.

			HOST <------------- VICTIM
			 	ACK: 10000
				SEQ: 20000
				LEN: 128
		
		     ATTACKER -------------> VICTIM
				ACK: 20128
				SEQ: 10000
				LEN: 64

		Once these are constructed we will encode application level headers and commands to truly take advantage of the session and our new identity.
		Depending on who was attacked you can either issue commands to a server posing as the user, or send fraudulent data to a user posing as the
		server.
	*/

}
