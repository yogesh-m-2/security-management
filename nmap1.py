import nmap

def scan_host_all():
	nm=nmap.PortScanner()
	res = nm.scan(hosts='192.168.0.0/24', arguments='-O -v')
	#print(res)
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			print("\n"+x+"\n")
			for keys in nm[x]:
				print(keys,nm[x][keys])
			
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