import nmap
import json

def nmap_scan_classA(sub_host):
	nm=nmap.PortScanner()
	print("starting"+str(sub_host))
	res = nm.scan(hosts='192.168.'+str(sub_host)+'.0/24', arguments='-O -v')
	keyvalues=None
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			keyvalues="\n"+x+"\n"
	#all_hosts=keyvalues
	

def scan_host_all(class_type):
	classA = '10.0.0.0','10.255.255.255'
	classB = '172.16.0.0','172.31.255.255'
	classC = '192.168.0.0','192.168.255.255'
	if(class_type=="A"):
		res = nm.scan(hosts='10.10-255.10-255.10-255/8', arguments='-O -v')
	if(class_type=="B"):
		res = nm.scan(hosts='172.16-31.0-255.0-255/16', arguments='-O -v')
	if(class_type=="C"):
		res = nm.scan(hosts='192.168.0-255.0-255', arguments='-O -v')
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			f=open("single_host_"+class_type+"_info.json","w")
			for x in nm.all_hosts():
				f.write(nm[x])
				f.close()
			
def scan_host_range(start,end):
	nm=nmap.PortScanner()
	res = nm.scan(hosts='192.168.0.0/24', arguments='-O -v')
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			print("\n"+x+"\n")
			for keys in nm[x]:
				print(keys,nm[x][keys])

def scan_single_host(host):
	nm=nmap.PortScanner()
	res=nm.scan(hosts=host, arguments='-O -v')
	print(nm[host])
	f=open("single_host_"+host+"_info.json","w")
	f.write(str(nm[host]).replace("'", "\""))
	f.close()

scan_single_host("192.168.0.105")