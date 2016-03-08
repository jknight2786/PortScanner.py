# PortScanner.py
A port scanner written for IT567
Performs port scanning on an IP address or range of IP addresses
IP range can be entered with net mask with slash notation, a range using -, or with a subnet mask using -s
Ex: 192.168.1.0/24, 192.168.1.0-255, 192.168.1.0 -s 255.255.255.0 are all equivalent
Multiple ports can be entered after -p with a space inbetween. Default port is 80
The type of scan can be changed to TCP, UDP, or ICMP using the --tcp, --udp, --icmp flags respectively. Default is TCP
A Xmas, FIN, or Null scan can be done using the --xmas, --fin, --null flags respectively
For each port on each host, the program will print whether the given port is open, closed, filtered, etc.

