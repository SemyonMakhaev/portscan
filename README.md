# Portscan

## The utility for host ports remote scanning

The program recognizes which port of a given host is opened 
and which is closed. Also it checks which protocol from list 
NTP, DNS, SMTP, FTP, POP3, HTTP works on a port of this host.

Program uses raw-sockets, so for correct working it requires 
administrator permissons. Else it can't scan UDP-ports, and 
there woudn't be no information about them.

ATTENTION! Don't forget to stop a firewall on your computer. 
The program cathes ICMP messages "port ureachable" and a 
firewall can block this packages. In this case an information 
about UDP-ports will be incorrect!

The program takes following arguments: host - an IP-address or 
a domain name of the target remote host; ports - any number of 
target ports. A port should be an integer between 0 and 65535. 

Program makes a table where given ports are indicated. For each 
port it recognizes is that port opened or closed and gives a 
name of protocol working on this port of this host, if it was 
able to got a protocol.

Notations: '+' means that a port is opened, '-' means that a port 
is closed, '?' means that there is no information about this 
position. Also a sign 'f' using for a filtering UDP-ports marking.

To call a help message use --help or -h argument.
