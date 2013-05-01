## WRATH
#### <i> What? Really? Another TCP Hijacker? </i>

<code># wrath [options] [operation] [filter] </code>

WRATH is a generic TCP hijacker capable of taking over TCP virtual circuits taking place 
on your LAN and injecting fabricated data into the circuit.

For example taking over a server's http connection to a client might look like this:

<code># ./wrath -f appheaders/takeover -o http "src host *client* and port 80"</code>

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

This performs a DoS on any packets whose IP source address matches 10.&#42;.&#42;.&#42; and does
not match the identifier specified by *me*.

##### Features to Come:
* HTTP Request Injection
* IRC Message Injection
* NTP Command Injection

_Dependencies_: libnet v1.1.6, libpcap v1.3

_Disclaimer_:
This project was heavily influenced by Jon Erickson's book, _Hacking:
The Art of Exploitation_. Many of the practices and techniques used in
this codebase I learned from that book.
