from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import json 


jmap={"maps":[]}

def make_json(maps):
	for i in maps:
		src,dst=i.split("-")
		data={"src":src,"dst":dst}
		jmap["maps"].append(data)
	host_map=json.dumps(jmap)
	with open("host_map.json","w") as f:
		f.write(host_map)

def analyze_pcap(file):
	pkts = rdpcap(file)
	maps=[]

	for pkt in pkts:
		if IP in pkt:
			if(str(str(pkt[IP].src)+"-"+str(pkt[IP].dst)) not in maps and str(str(pkt[IP].dst)+"-"+str(pkt[IP].src)) not in maps):
				sent=str(pkt[IP].src)+"-"+str(pkt[IP].dst)
				maps.append(sent)
	make_json(maps)
