

# Network Tools Script using Scapy\
\
This script provides various network tools utilizing the Scapy library for tasks such as pinging a host, performing DNS queries, conducting SYN scans, sniffing network packets, and creating graphical packet dumps.\
\
## Requirements\
\
- Python 3.x\
- Scapy\
- PyX\
\
## Installation\
\
1. **Install Python 3**: Ensure you have Python 3 installed. You can download it from [python.org](https://www.python.org/).\
\
2. **Install Scapy**: You can install Scapy using pip:\
   ```bash\
   pip install scapy\
   ```\
\
3. **Install PyX**: You can install PyX using pip:\
   ```bash\
   pip install pyx\
   ```\
\
## Usage\
\
You can use this script to perform various network-related tasks. Below are the command-line arguments you can use with this script:\
\
### Ping a Host\
\
To ping a host, use the `--ping` argument followed by the hostname or IP address:\
```bash\
python scanner.py --ping www.google.com\
```\
\
### DNS Query\
\
To perform a DNS query, use the `--dns` argument followed by the domain name:\
```bash\
python scanner.py --dns mdx.ac.ae\
```\
\
### SYN Scan\
\
To conduct a SYN scan on a specific port of a host, use the `--synscan` argument followed by the host and port in the format `host:port`:\
```bash\
python scanner.py --synscan scanme.nmap.org:80\
```\
\
### Sniff Packets\
\
To sniff packets on a specific network interface, use the `--sniff` argument followed by the interface name:\
```bash\
python scanner.py --sniff eth0\
```\
\
### Graphical Packet Dump\
\
To create a graphical dump of a packet and save it as a PDF, use the `--graph` argument:\
```bash\
python scanner.py --graph\
```\
\
## Examples\
\
### Ping a Host\
\
```bash\
python scanner.py --ping www.google.com\
```\
\
### Perform a DNS Query\
\
```bash\
python scanner.py --dns mdx.ac.ae\
```\
\
### Conduct a SYN Scan\
\
```bash\
python scanner.py --synscan scanme.nmap.org:80\
```\
\
### Sniff Packets on an Interface\
\
```bash\
python scanner.py --sniff eth0\
```\
\
### Create a Graphical Packet Dump\
\
```bash\
python scanner.py --graph\
```\
\
## License\
\
This project is licensed under the MIT License. See the LICENSE file for details.\
\
---\
\
Feel free to customize this README file further to suit your needs.}
