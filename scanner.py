import argparse
from scapy.all import *
from scapy.utils import *
from pyx import *

def ping_host(host):
    print("\nPinging host:", host)
    packet = IP(dst=host)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)  # Send the packet and receive a response
    if response:
        response.show()

def dns_query(domain):
    print("\nDNS Query for domain:", domain)
    packet = IP(dst="8.8.8.8")/UDP()/DNS(rd=1, qd=DNSQR(qname=domain))
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        response.show()

def syn_scan(host, port):
    print("\nSYN Scan on", host, "port", port)
    packet = IP(dst=host)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print("Port", port, "is open")
        sr(IP(dst=host)/TCP(dport=port, flags='R'), timeout=1, verbose=0)  # Sending RST to close the connection
    else:
        print("Port", port, "is closed or filtered")

def sniff_packets(interface, count=5):
    print("\nSniffing", count, "packets on", interface)
    packets = sniff(iface=interface, count=count)
    packets.summary()

def graph_packet():
    print("\nGraphical dump of a packet")
    packet = IP(dst="8.8.8.8")/ICMP()
    
     # Render the packet using PyX
    packet_canvas = Canvas()
    packet.pdfdump("packet_diagram.pdf", canvas=packet_canvas)

    print("Packet diagram has been saved as 'packet_diagram.pdf'.")
    

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network tools script using Scapy")
    
    parser.add_argument("--ping", help="To ping a host: ./scanner.py --ping www.google.com")
    parser.add_argument("--dns", help="To perform a DNS query: ./scanner.py --dns mdx.ac.ae")
    parser.add_argument("--synscan", help="To conduct a SYN scan on port 80 of a host: ./scanner.py --synscan scanme.nmap.org:80")
    parser.add_argument("--sniff", help="To sniff packets on an interface: ./scanner.py --sniff eth0")
    parser.add_argument("--graph", action="store_true", help="To display a graphical dump of a packet: ./scanner.py --graph")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    if args.ping:
        ping_host(args.ping)
    if args.dns:
        dns_query(args.dns)
    if args.synscan:
        host, port = args.synscan.split(':')
        syn_scan(host, int(port))
    if args.sniff:
        sniff_packets(args.sniff)
    if args.graph:
        graph_packet()
