import socket

import os
import struct
from ctypes import *

import threading
import time
from netaddr import IPNetwork, IPAddress


# Host to listen on 
host = "192.168.1.145"

# Subnet to target
subnet = "192.168.1.1/24"

# Message we'll check ICMP responses for
message = "HACKY-HACKY-HACK!"

# This sprays out the UDP datagrams
def udp_sender(subnet, message):
	time.sleep(5)
	sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	for ip in IPNetwork(subnet):
		try : 
			sender.sendto(message, ("%s" %ip, 65212))
		except :
			pass 


# our IP header
class IP(Structure):
	_fields_ = [

		("ihl", c_ubyte, 4),
		("version", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort ),
		("offset", c_ushort),
		("ttl", c_ubyte),
		("protocol_num", c_ubyte),
		("sum", c_ushort),
		("src", c_ulong),
		("dst", c_ulong)

	]

	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):

		# map protocolo constants to their names
		self.protocol_map = {1 : "ICMP", 6:"TCP", 17:"UDP"}

		# Human readable IP addresses
		self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

		# Human readable protocol
		try :
			self.protocol = self.protocol_map[self.protocol_num]
		except :
			self.protocol = str(self.protocol_num)

# ICMP header

class ICMP(Structure):

	_fields_ = [
		("type", c_ubyte),
		("code", c_ubyte),
		("checksum", c_ushort),
		("unused", c_ushort),
		("next_hop_mtu", c_ushort)

	]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self,socket_buffer):
		pass

if os.name == "nt" :
	socket_protocol = socket.IPPROTO_IP

else :
	socket_protocol = socket.IPPROTO_ICMP



sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt" :
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Start sending packets
t = threading.Thread(target=udp_sender, args=(subnet, message))
t.start()



try :
	while True :

		# read in a packet 
		raw_buffer = sniffer.recvfrom(65565)[0]

		# Create an IP header from the first 20 bytes of the buffer
		ip_header = IP(raw_buffer[0:20])

		# Print out the protocol that was detected and the hosts
		

		# If it's ICMP, we want it
		if ip_header.protocol == "ICMP" :

			
			# Calculate where our ICMP packet starts 
			offset = ip_header.ihl * 4

			# Get ICMP header
			buf  = raw_buffer[offset:offset + sizeof(ICMP)]

			# Create our ICMP structure
			icmp_header = ICMP(buf)
			#print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
			#print ("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

			# now check for the TYPE 3 and CODE
			if icmp_header.code == 3 and icmp_header.type == 3 :

				# Make sure host is in our target subnet 
				if IPAddress(ip_header.src_address) in IPNetwork(subnet):

					# Make sure it has our message
					if raw_buffer[len(raw_buffer) - len(message):] == message :
						print ("Host up: %s" %ip_header.src_address)



# Handle CTRL-C

except KeyboardInterrupt :

	# If we're using Windows, turn off promiscuous mode
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
