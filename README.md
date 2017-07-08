# Description
UDP traceroute utility to check UDP path through a network

# Installation
Install the scapy module:
```
pip install scapy
```

# Usage
Assign execute permission to the script:
```
chmod a+x udp_traceroute.py
```

Show the available options:
```
# ./udp_traceroute.py --help
usage: udp_traceroute.py [-h] [-i iface] [-m maxttl] [-t timeout] [-p port]
                         host [host ...]

UDP traceroute utility to check if a UDP port is open

positional arguments:
  host        IP/hostname of the target

optional arguments:
  -h, --help  show this help message and exit
  -i iface    interface on which to send packets
  -m maxttl   max TTL of UDP packet (default 30)
  -t timeout  time in seconds to run the traceroute (default 5)
  -p port     destination UDP port to check (default 53)
```

Sample output:
```
# ./udp_traceroute.py 8.8.8.8 -p 53 -m 10
Begin emission:
**Finished to send 10 packets.
*******.....
Received 14 packets, got 9 answers, remaining 1 packets
   8.8.8.8:udp53      
1  192.168.0.1     11 
2  192.168.1.100   11 
3  125.235.249.190 11 
4  125.235.249.209 11 
5  27.68.237.133   11 
6  27.68.250.250   11 
7  72.14.196.68    11 
9  64.233.175.89   11 
10 8.8.8.8    
```
_**Note**: The value "11" in the output is the ICMP type (TTL exceeded in transit)_
