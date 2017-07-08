#!/usr/bin/env python
#
# UDP traceroute utility using scapy module

from __future__ import print_function

import argparse
import logging
import socket
import sys

try:
    from scapy.all import *
except ImportError:
    print("Scapy module has not been installed on this system.")
    print("Download it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def udp_trace(host, iface, maxttl, timeout, dport):
    
    """ UDP traceroute """
    
    if dport == 123:  # NTP
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=123, dport=123) / NTPHeader(dispersion=66192L, recv=0L, precision=250L, ref_id="\x00\x00\x00\x00", delay=0L, leap=3L, version=3L, mode=1L, stratum=0L, poll=10L, ref=0L, id=None, sent=14195914391047827090L, orig=0L), iface=iface)
        
    elif dport == 69:  # TFTP
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=69) / TFTP(op=1) / TFTP_RRQ(mode="octet", filename="rfc1350.txt"), iface=iface)
        
    elif dport == 53:  # DNS
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=53) / DNS(aa=0L, qr=0L, an=None, ad=0L, nscount=0, qdcount=1, ns=None, tc=0L, rd=1L, arcount=0, ar=None, opcode=0L, ra=0L, cd=0L, z=0L, rcode=0L, id=31704, ancount=0, qd=DNSQR(qclass=1, qtype=1, qname="www.google.com.")), iface=iface)
        
    elif dport == 161:  # SNMP get
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=161) / SNMP(PDU=SNMPget(error_index=0, varbindlist=[SNMPvarbind(oid=[".1.3.6.1.2.1.1.2.0"])], id=38, error=0), version=0, community="public"), iface=iface)                                                                                                                                                                       
        
    elif dport == 162:  # SNMP trap
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=162) / SNMP(PDU=SNMPtrapv1(agent_addr="127.0.0.1", generic_trap=0, enterprise=".1.3.6.1.4.1.4.1.2.21", varbindlist=[SNMPvarbind(oid=[".1.3.6.1.2.1.2.1.0"], value=33)], time_stamp=0, specific_trap=0), version=0, community="public"), iface=iface)
        
    elif dport == 1812:  # Radius authentication
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=1812) / Radius(authenticator="\xec\xfe=/\xe4G>\xc6)\x90\x95\xeeF\xae\xdfw", attributes=[RadiusAttribute(type=4, value="\n\x00\x00\x01", len=6), RadiusAttribute(type=5, value="\x00\x00\xc3\\", len=6), RadiusAttribute(type=61, value="\x00\x00\x00\x0f", len=6), RadiusAttribute(type=1, value="John.McGuirk", len=14), RadiusAttribute(type=30, value="00-19-06-EA-B8-8C", len=19), RadiusAttribute(type=31, value="00-14-22-E9-54-5E", len=19), RadiusAttribute(type=6, value="\x00\x00\x00\x02", len=6), RadiusAttribute(type=12, value="\x00\x00\x05\xdc", len=6), RadiusAttribute(type=79, value="\x02\x00\x00\x11\x01John.McGuirk", len=19), RadiusAttribute(type=80, value="(\xc5\xbe\xb8\x84$\x86\xdap\xdbQ1o\x9dx\x89", len=18)], code=1, id=5, len=139), iface=iface)
        
    elif dport == 1813:  # Radius accounting
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=1813) / Radius(authenticator="C\xb4\x05q\x15R\x19o\xf3\xd5\x1f\x93\xb2\xe5\nj", attributes=[RadiusAttribute(type=1, value="mu", len=4), RadiusAttribute(type=4, value="\x0a\x00\x00\x01", len=6), RadiusAttribute(type=40, value="\x00\x00\x00\x01", len=6), RadiusAttribute(type=44, value="9668ab55", len=10)], code=4, id=1, len=46), iface=iface)
        
    elif dport == 514:  # Syslog
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=514) / Raw(load="<29>Dec  7 14:58:31 SEL-3620B Login: Login successful by: admin at 192.168.1.101\n"), iface=iface)
        
    else:  # Other UDP ports
        ans, unans = traceroute(host, maxttl=maxttl, timeout=timeout, l4=UDP(sport=RandShort(), dport=dport) / Raw(load="1234567890" * 10), iface=iface)


def main():
    
    """ Main function """
    
    parser = argparse.ArgumentParser(description="UDP traceroute utility to check if a UDP port is open")
    parser.add_argument("host", nargs="+", help="IP/hostname of the target")
    parser.add_argument("-i", metavar="iface", help="interface on which to send packets")
    parser.add_argument("-m", metavar="maxttl", type=int, default=30, help="max TTL of UDP packet (default 30)")
    parser.add_argument("-t", metavar="timeout", type=int, default=5, help="time in seconds to run the traceroute (default 5)")
    parser.add_argument("-p", metavar="port", type=int, default=53, help="destination UDP port to check (default 53)")
    args = parser.parse_args()
    if not 1 <= args.m <= 255:
        print("Max TTL value must be in range 1-255.")
        sys.exit()
    try:
        udp_trace(args.host, args.i, args.m, args.t, args.p)
    except socket.error:
        print("Wrong interface and/or not run as superuser.")
        sys.exit()


if __name__ == "__main__":
    main()
