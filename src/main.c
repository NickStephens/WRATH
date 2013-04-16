#include "stdlib.h"
#include "wrath.h"

int main(int argc, char *argv[]) {

	struct arg_values *user_values;
	user_values = (struct arg_values *) malloc(sizeof (struct arg_values));
	arg_eval(argc, argv, user_values);	

	wrath_position(user_values);

	free(user_values);
	/* Algorithm
		first sniff a packet that matches the berkeley packet filter syntax (the expression will be delivered via wrath-argj)
		NOTE: The packet's origin address is the address representing who will recieve our spoofed information. The packet's 
		desitinated address represents the machine we will pose as. 
	
		Information will be inferred from the sniffed packet used to construct low-level headers (IP, TCP (Mayber ETHER if they share a subnet))

		The sniffed packets SEQ,ACK, and packet length numbers are critical. With these we will forge a packet destined for the source
		pretending to be the packet's original desitination.

			VICTIM <------------- HOST 
			 	ACK: 10000
				SEQ: 20000
				LEN: 128
		
		     ATTACKER -------------> HOST 
				ACK: 20128
				SEQ: 10000
				LEN: 64

		Once these are constructed we will encode application level headers and commands to truly take advantage of the session and our new identity.
		Depending on who was attacked you can either issue commands to a server posing as the user, or send fraudulent data to a user posing as the
		server.
	*/

}
