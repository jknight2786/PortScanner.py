#Jon Knight, IT567 Win2016, Port scanner
#Performs port scanning on an IP address or range of IP addresses
#IP range can be entered with net mask with slash notation, a range using -, or with a subnet mask using -s
#Multiple ports can be entered after -p with a space inbetween
#Ex: 192.168.1.0/24, 192.168.1.0-255, 192.168.1.0 -s 255.255.255.0 are all equivalent
#! /usr/bin/env python
import sys
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import *

#Parses arguments for options
parser = argparse.ArgumentParser()
parser.add_argument('ip_address', help='IP address or range to scan')
parser.add_argument('-s', '--subnet-mask', help='Subnet mask to use', metavar='subnet_mask')
parser.add_argument('-p', metavar='Ports', help='Ports to scan', 
default=80, type=int, nargs='+')
parser.add_argument('-t', '--traceroute', help='Performs a traceroute to the given host', action='store_true')
parser.add_argument('--icmp', help='Uses icmp packets', action='store_true')
parser.add_argument('--tcp', help='Uses tcp packets', default=True, action='store_true')
parser.add_argument('--udp', help='Uses udp packets', action='store_true')
parser.add_argument('--xmas', help='Performs an Xmas scan', action='store_true')
parser.add_argument('--fin', help='Performs a FIN scan', action='store_true')
parser.add_argument('--null', help='Performs a Null scan', action='store_true')

args = parser.parse_args()
print args
if "-" not in args.ip_address:
	if args.subnet_mask != None:
		IPvals = IPNetwork(args.ip_address + '/' + args.subnet_mask)
		#print IP
	else:
		IPvals = IPNetwork(args.ip_address)
else:
	dash = args.ip_address.find('-')
	dot = args.ip_address.rfind('.')
	IPvals = IPRange(args.ip_address[:dash], args.ip_address[:dot+1] + args.ip_address[dash+1:])

if args.udp or args.icmp or args.traceroute or args.xmas or args.fin or args.null:
	args.tcp = False

for host in IPvals:
	s = str(host)
	print s
	ip = IP(dst=str(host))
	if(args.icmp):
		#ICMP packet (ping)
		ip = ip/ICMP(dport=port)
		response = sr1(ip, timeout=5)
		if(str(type(response)) == "<type 'NoneType'>"):
			print 'No response'
		elif(response.haslayer(ICMP) and response.getlayer(ICMP).code == 0):
			print 'Host is up'
		else:
			print 'Error'
	elif(args.traceroute):
		#Performs TCP traceroute with 30 max hops
		traceroute(host, maxttl=30)
	elif(args.xmas):
		ip = ip/TCP(dport=port,flags="FPU")
		response = sr1(ip, timeout=5)
		#No response means port is open
		if(str(type(response)) == "<type 'NoneType'>"):
			print 'Open'
		#Reset means port is closed
		elif(response.haslayer(TCP) and response.getlayer(TCP).flags == 4):
			print 'Closed'	
		#Other response (ICMP error) means port is filtered
		else:
			print 'Filtered'
	elif(args.fin):
		ip = ip/TCP(dport=port,flags="F")
		response = sr1(ip, timeout=5)
		#No response means port is open
		if(str(type(response)) == "<type 'NoneType'>"):
			print 'Open'
		#Reset means port is closed
		elif(response.haslayer(TCP) and response.getlayer(TCP).flags == 4):
			print 'Closed'	
		#Other response (ICMP error) means port is filtered
		else:
			print 'Filtered'
	elif(args.null):
		ip = ip/TCP(dport=port,flags="")
		response = sr1(ip, timeout=5)
		#No response means port is open
		if(str(type(response)) == "<type 'NoneType'>"):
			print 'Open'
		#Reset means port is closed
		elif(response.haslayer(TCP) and response.getlayer(TCP).flags == 4):
			print 'Closed'	
		#Other response (ICMP error) means port is filtered
		else:
			print 'Filtered'			
	else:
		for port in args.p:
			print 'Port ' + str(port) + ': '
			if(args.udp):
				ip = ip/UDP(dport=port)
				response = sr1(ip, timeout=5)
				#No response is inconclusive
				if(str(type(response)) == "<type 'NoneType'>"):
					print 'Open|Filtered'
				#UDP response means port is open
				elif(response.haslayer(UDP)):
					print 'Open'
				#Other response means port is filtered unless ICMP code is 3
				else:
					if(response.haslayer(ICMP) and response.getlayer(ICMP).code == 3):
						print 'Closed'
					else:
						print 'Filtered'	
			else:
				#TCP Syn packet
				ip = ip/TCP(dport=port,flags="S")
				response = sr1(ip, timeout=5)
				if(str(type(response)) == "<type 'NoneType'>"):
					print 'Filtered'
				#SynAck packet
				elif(response.haslayer(TCP) and response.getlayer(TCP).flags == 18):
					print 'Open'
				#ResetAck packet
				elif(response.haslayer(TCP) and response.getlayer(TCP).flags == 6):
					print 'Closed'
				else:
					print 'Filtered'


		
		
	

	
	


