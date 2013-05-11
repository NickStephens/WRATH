## WRATH
#### <i> What? Really? Another TCP Hijacker? </i>

<code># wrath [options] [filter] </code>

WRATH is a generic TCP hijacker capable of taking over TCP virtual circuits taking place 
on your LAN and injecting fabricated data into the circuit.

##### What makes WRATH generic?

WRATH is generic because it can hijack any unconfidential (unencrypted) or unauthorized
protocol by simply providing a valid-looking payload and protocol search string. When
an operation is given that WRATH doesn't recognize it will then just search for the given
pattern in the captured packet's application header. If a match is found within the 
captured packet's application header, WRATH will inject a packet with the payload contained 
in the file or command specified, and effectively forging a response to the captured packet.

> RECOGNIZED OPERATIONS: <br>
> http-response <br>
> http-request <br>
> irc <br>
> tcp <br>
> no-string (for any packet which contains application data) <br>

##### How WRATH works:

TCP Hijacking is a network-based attack which spoofs certain packet headers to inject fraudulent data
as the host. It does this by sniffing network traffic and doing some arithmetic to predict what a legitimate
packet in the virtual circuit may look like. As far as TCP is concerned, sequence and acknowledge numbers are
the only form of authentication. Any packet, no matter who writes it, with legitimate a looking IP address, sequence
number, and acknowledge number will be considered valid by the recipient.

When WRATH sees a request made for a resource, it reads the request's source IP address, destination IP address, TCP source
port, TCP destination port, TCP sequence number, and TCP acknowledgement number. With this information it then crafts a
packet to look like it belongs to the destination and within the same virtual circuit. 

###### Where SSL Comes Into Play

With SSL things become a bit more difficult for WRATH, and the presence of SSL on a virtual circuit definitely weakens
WRATH's abilities; however the mere presence of SSL is not the end for WRATH. TCP's sequence and acknowledgement numbers
are still in plaintext. With WRATH we can easily snoop on these and forge data inside the plain TCP header at-will. Anything
beyond the TCP header with SSL is out-of-bounds, because of the way it authenticates data, you'd have to know the secret key
of the transaction to properly pose as either host in the connection.

##### Examples:

For example taking over a server's http connection to a client might look like this:

<code># ./wrath -a appheaders/takeover -o http-resp "src host *client* and port 80"</code>

This will hijack all HTTP connections responding to the *client* and append the file 
appheaders/takeover to the attacking packet's payload. (HTTP Response hijacking actually 
involves a few more steps, but this is the premise). If appheaders/takeover contains 
a valid HTTP response header and valid HTML then the HTML will render in the victim's
browser, displaying data of your choice.

A simpler DoS attack may look like this:

<code># ./wrath -o tcp -tR "src host *client*" </code>

This command hijacks all connections originating from *client* and marks the TCP RST flag, 
effectively telling the client that all server's are denying its connection.

The above examples have one problem: they only target a single victim on the LAN.

This can easily change, because WRATH uses the Berkely Packet Filter syntax to determine which packets
are captured, we can modify the attacks to affect an entire network.

<code># ./wrath -o tcp -tR "src net 10 and not host *me*"</code>

This performs a DoS on any connections whose IP source address matches 10.&#42;.&#42;.&#42; and does
not match the identifier specified by *me*.

_Dependencies_: libnet v1.1.6, libpcap v1.3

_Disclaimer_:
* This tool is intended for educational purposes only and is not
intended for any illegal activities. The author is not responsible
for any harm caused by this tool.
* This project was heavily influenced by Jon Erickson's book, _Hacking:
The Art of Exploitation_. Many of the practices and techniques used in
this codebase I learned from that book.
