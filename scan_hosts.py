import nmap
import json
import re


def format_to_json(jhost,start,end):
	reformatted=re.sub("(\w+): {", r'"\1": {', jhost[1:])
	f=open("range_host_"+str(start)+str(end)+"_info.json","w")
	f.write('{'+str(reformatted).replace("'", "\"")+'}')
	f.close()


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
		res = nm.scan(hosts='192.168.0-255.0-255/24', arguments='-O -v')
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			f=open("single_host_"+class_type+"_info.json","w")
			for x in nm.all_hosts():
				f.write(nm[x])
				f.close()
			

def scan_host_range(start,end):
	jhost=""
	nm=nmap.PortScanner()
	sclass=start.split(".")
	eclass=end.split(".")
	if(sclass[0]==eclass[0]):
		if(sclass[0]=="192"):
			host="192.168."+sclass[2]+"-"+eclass[2]+"."+sclass[3]+"-"+eclass[3]+""
			res = nm.scan(hosts=host, arguments='-O -v')
			for x in nm.all_hosts():
				if(nm[x]['status']['state']=="up"):
					jformat=str(nm[x])
					jhost=jhost+","+'"'+x+'":'+jformat
			format_to_json(jhost,start,end)
			
		elif(sclass[0]=="10"):
			if(0<=int(sclass[1])<=255 and 0<=int(sclass[2])<=255 and 0<=int(sclass[3])<=255 and 0<=int(eclass[1])<=255 and 0<=int(eclass[2])<=255 and 0<=int(eclass[3])<=255):
				host="10."+sclass[1]+"-"+eclass[1]+"."+sclass[2]+"-"+eclass[2]+"."+sclass[3]+"-"+eclass[3]+""
				res = nm.scan(hosts=host, arguments='-O -v')
				for x in nm.all_hosts():
					if(nm[x]['status']['state']=="up"):
						jformat=str(nm[x])
						jhost=jhost+","+'"'+x+'":'+jformat
				format_to_json(jhost,start,end)
			else:
				print("invalid address format")
		elif(sclass[0]=="172"):
			if(16<=int(sclass[1])<=31 and 0<=int(sclass[2])<=255 and 0<=int(sclass[3])<=255 and 16<=int(eclass[1])<=31 and 0<=int(eclass[2])<=255 and 0<=int(eclass[3])<=255):
				host="172."+sclass[1]+"-"+eclass[1]+"."+sclass[2]+"-"+eclass[2]+"."+sclass[3]+"-"+eclass[3]+""
				res = nm.scan(hosts=host, arguments='-O -v')
				for x in nm.all_hosts():
					if(nm[x]['status']['state']=="up"):
						jformat=str(nm[x])
						jhost=jhost+","+'"'+x+'":'+jformat
				format_to_json(jhost,start,end)
			else:
				print("invalid address format")
		else:
			print("invalid address format")
	

def scan_single_host(host):
	nm=nmap.PortScanner()
	res=nm.scan(hosts=host, arguments='-O -v')
	print(nm[host])
	f=open("single_host_"+host+"_info.json","w")
	f.write(str(nm[host]).replace("'", "\""))
	f.close()


scan_host_range("192.168.0.100","192.168.0.105")