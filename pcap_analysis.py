from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


# IP characteristics
ip_version = ihl = tos = ilen = id = iflags = frag = ttl = proto = ichksum = src = dst = ioptions = ""
# TCP characteristics
tsport = tdport = seq = ack = dataofs = reserved = window = tflags = tchksum = urgptr = toptions = ""
tflag_fin = tflag_syn = tflag_rst = tflag_psh = tflag_ack = tflag_urg = tflag_ece = tflag_cwr = ""

# UDP characteristics
usport = udport = ulen = uchksum = ""

def analyze_pcap(file):
	pkts = rdpcap(file)
	
	maps=[]

	for pkt in pkts:
		if IP in pkt:
			if(str(str(pkt[IP].src)+"-"+str(pkt[IP].dst)) not in maps and str(str(pkt[IP].dst)+"-"+str(pkt[IP].src)) not in maps):
				sent=str(pkt[IP].src)+"-"+str(pkt[IP].dst)
				maps.append(sent)
	print(maps)

analyze_pcap("packets.pcap")
