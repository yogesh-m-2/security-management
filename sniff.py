from scapy.all import *
import socket
import datetime
import os
import time
import json
import csv

jdict_tcp={"datetime":None,"src-mac":None,"dst-mac":None,"src-port":None,"dst-port":None,"src-ip":None,"dst-ip":None}
jdict_udp={"datetime":None,"src-mac":None,"dst-mac":None,"src-port":None,"dst-port":None,"src-ip":None,"dst-ip":None}
jdict_icmp={"datetime":None,"src-mac":None,"dst-mac":None,"src-port":None,"dst-port":None,"src-ip":None,"dst-ip":None}

def write_csv(data):
	data_file = open('data_file.csv', 'a')
	csv_writer = csv.writer(data_file)
	data=json.loads(data)
	data['src-ip']
	csv_writer.writerow(data['src-ip'])
def network_sniffing(pkt):
	time=datetime.datetime.now()
	if pkt.haslayer(TCP):
		jdict_tcp["datetime"]=str(time)
		jdict_tcp["src-mac"]=str(pkt.src)
		jdict_tcp["dst-mac"]=str(pkt.dst)
		jdict_tcp["src-port"]=str(pkt.sport)
		jdict_tcp["dst-port"]=str(pkt.dport)
		jdict_tcp["src-ip"]=str(pkt[IP].src)
		jdict_tcp["dst-ip"]=str(pkt[IP].dst)
		#print(json.dumps(jdict_tcp))
		write_csv(json.dumps(jdict_tcp))

	if pkt.haslayer(UDP):
		jdict_udp["datetime"]=str(time)
		jdict_udp["src-mac"]=str(pkt.src)
		jdict_udp["dst-mac"]=str(pkt.dst)
		jdict_udp["src-port"]=str(pkt.sport)
		jdict_udp["dst-port"]=str(pkt.dport)
		jdict_udp["src-ip"]=str(pkt[IP].src)
		jdict_udp["dst-ip"]=str(pkt[IP].dst)
		#print(json.dumps(jdict_udp))
		write_csv(json.dumps(jdict_udp))

	if pkt.haslayer(ICMP):
		jdict_icmp["datetime"]=str(time)
		jdict_icmp["src-mac"]=str(pkt.src)
		jdict_icmp["dst-mac"]=str(pkt.dst)
		jdict_icmp["src-ip"]=str(pkt[IP].src)
		jdict_icmp["dst-ip"]=str(pkt[IP].dst)
		#print(json.dumps(jdict_icmp))
		write_csv(json.dumps(jdict_icmp))

if __name__ == '__main__':
	sniff(prn=network_sniffing)