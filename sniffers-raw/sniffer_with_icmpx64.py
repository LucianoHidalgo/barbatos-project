import socket

import os
import struct
from ctypes import *

# Host to listen on
host = "192.168.1.149"

# our IP header
class IP(Structure):
	_fields_ = [

		("ihl", c_uint8, 4),
		("version", c_uint8, 4),
		("tos", c_uint8),
		("len", c_uint16),
		("id", c_uint16 ),
		("offset", c_uint16),
		("ttl", c_uint8),
		("protocol_num", c_uint8),
		("sum", c_uint16),
		("src", c_uint32),
		("dst", c_uint32)

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
		("type", c_uint8),
		("code", c_uint8),
		("checksum", c_uint16),
		("unused", c_uint16),
		("next_hop_mtu", c_uint16)

	]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self,socket_buffer):
		pass

#
if os.name == "nt" :
	socket_protocol = socket.IPPROTO_IP

else :
	socket_protocol = socket.IPPROTO_ICMP


sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt" :
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


try :
	while True :

		# read in a packet
		raw_buffer = sniffer.recvfrom(65565)[0]

		# Create an IP header from the first 20 bytes of the buffer
		ip_header = IP(raw_buffer[0:20])

		# Print out the protocol that was detected and the hosts
		print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

		# If it's ICMP, we want it
		if ip_header.protocol == "ICMP" :

			# Calculate where our ICMP packet starts
			offset = ip_header.ihl * 4

			# Get ICMP header
			buf  = raw_buffer[offset:offset + sizeof(ICMP)]

			# Create our ICMP structure
			icmp_header = ICMP(buf)

			print ("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))



# Handle CTRL-C

except KeyboardInterrupt :

	# If we're using Windows, turn off promiscuous mode
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
