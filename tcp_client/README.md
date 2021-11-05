# Simple TCP Test Client

A simple PoW TCP client that sets its ISN (Initial Sequence Number)
to the second round truncated sha256 hash of a given secret combined with sport, dport and saddr. This is used
for connecting to rootkit ports that are hidden by port knocking.

Since this client makes use of raw sockets to set the ISN separately,
it has to run as root.

## Functionality
This TCP client sends a TCP SYN to the corresponding server with the upper 4 bytes of the
sha256 hash of a hased shared secret, concatenated with sport, dport and saddr, as ISN.
If the server response with a TCP ACK RST or a timeout occurs, then the socket is either closed,
or it is filtered via our port_knocking mechanism.
In contrast, if we receive a TCP SYN ACK, we have successfully authorized to the server.

## Dependencies
For sha256 hashing the tcp client depends on openssl:

``sudo apt-get install libssl-dev``

## Compile
Use the Makefile:

``make``

## Usage
Create a TCP client and connect to a knocked port using a secret:

``./tcp_client <interface> <ip> <port> <secret>``

The network interface parameter is required to get the src ip of the packet. Be sure that
the interface identifier exists. You can check this via a net-tool, such as 'ifconfig'.
The ip can be either in ipv4 or in ipv6 format. The secret describes the unhashed shared secret.

Examples:
* IPv4 localhost: ``sudo ./tcp_client lo0 127.0.0.1 4444 "this_is_my_shared_secret"``
* IPv6 localhost: ``sudo ./tcp_client lo0 ::1 4444 "this_is_my_shared_secret"``
* IPv4 remote host via en0: ``sudo ./tcp_client en0 217.4.23.3 4444 "this_is_my_shared_secret"``
