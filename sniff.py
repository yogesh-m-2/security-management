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

if(not(os.path.exists("data_file.csv"))):
	header=['src','dst']
	heads = open('data_file.csv', 'w')
	csv_writer = csv.writer(heads)
	csv_writer.writerow(header)
	heads.close()




def read_csv_check(data):
	read_data_file = open('data_file.csv', 'r')
	csv_reader = csv.reader(read_data_file)
	flag=0
	for line in csv_reader:
		if(str(str(line[0])+"-"+str(line[1])) == data or str(str(line[1])+"-"+str(line[0])) == data ):
			flag=1
	read_data_file.close()
	if(flag==0):
		return 1
	else:
		return 0

def write_csv(data):
	write_data_file = open('data_file.csv', 'a')
	csv_writer = csv.writer(write_data_file)
	csv_writer.writerow([str(data["src-ip"]),str(data["dst-ip"])])
	write_data_file.close()

def check_map_exist(data):
	data=json.loads(data)
	cmb_string=str(data["src-ip"])+"-"+str(data["dst-ip"])
	res=read_csv_check(str(cmb_string))
	if(res==1):
		write_csv(data)
		return(data)
	

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
		print(check_map_exist(json.dumps(jdict_tcp)))

	if pkt.haslayer(UDP):
		jdict_udp["datetime"]=str(time)
		jdict_udp["src-mac"]=str(pkt.src)
		jdict_udp["dst-mac"]=str(pkt.dst)
		jdict_udp["src-port"]=str(pkt.sport)
		jdict_udp["dst-port"]=str(pkt.dport)
		jdict_udp["src-ip"]=str(pkt[IP].src)
		jdict_udp["dst-ip"]=str(pkt[IP].dst)
		print(check_map_exist(json.dumps(jdict_udp)))

	if pkt.haslayer(ICMP):
		jdict_icmp["datetime"]=str(time)
		jdict_icmp["src-mac"]=str(pkt.src)
		jdict_icmp["dst-mac"]=str(pkt.dst)
		jdict_icmp["src-ip"]=str(pkt[IP].src)
		jdict_icmp["dst-ip"]=str(pkt[IP].dst)
		#print(json.dumps(jdict_icmp))
		print(check_map_exist(json.dumps(jdict_icmp)))



#sniff(prn=network_sniffing)