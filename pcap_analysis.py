from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import json 


jmap={"maps":[]}

def get_host_remove_duplicates(host_map):
	hosts=[]
	host_map=json.loads(host_map)
	for ip in host_map["maps"]:
		if(ip["src"] not in hosts):
			hosts.append(ip["src"])
		if(ip["dst"] not in hosts):
			hosts.append(ip["dst"])
	return(hosts)

def make_json(maps):
	for i in maps:
		src,dst=i.split("-")
		data={"src":src,"dst":dst}
		jmap["maps"].append(data)
	host_map=json.dumps(jmap)
	with open("host_map.json","w") as f:
		f.write(host_map)
	return (host_map)

def analyze_pcap(file):
	pkts = rdpcap(file)
	maps=[]
	for pkt in pkts:
		if IP in pkt:
			if(str(str(pkt[IP].src)+"-"+str(pkt[IP].dst)) not in maps and str(str(pkt[IP].dst)+"-"+str(pkt[IP].src)) not in maps):
				sent=str(pkt[IP].src)+"-"+str(pkt[IP].dst)
				maps.append(sent)
	host_map=make_json(maps)
	host_list=get_host_remove_duplicates(host_map)
	return(host_map,host_list)


print(analyze_pcap("packets.pcap"))