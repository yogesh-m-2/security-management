import nmap
import threading

# for keys in nm[x]:
# 				print(keys,nm[x][keys])

all_hosts = ""
def nmap_scan_classA(sub_host):
	nm=nmap.PortScanner()
	print("starting"+str(sub_host))
	res = nm.scan(hosts='192.168.'+str(sub_host)+'.0/24', arguments='-O -v')
	keyvalues=None
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			keyvalues="\n"+x+"\n"
	#all_hosts=keyvalues
	

def scan_host_all():
	classA = '10.0.0.0','10.255.255.255'
	classB = '172.16.0.0','172.31.255.255'
	classC = '192.168.0.0','192.168.255.255'
	for i in range(0,15):
		ti = threading.Thread(target=nmap_scan_classA, args=(i,))
		ti.start()
	print(all_hosts)
			
def scan_host_range(start,end):
	nm=nmap.PortScanner()
	res = nm.scan(hosts='192.168.0.0/24', arguments='-O -v')
	#print(res)
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			print("\n"+x+"\n")
			for keys in nm[x]:
				print(keys,nm[x][keys])


scan_host_all()