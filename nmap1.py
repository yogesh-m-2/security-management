import nmap

def p():
	nm=nmap.PortScanner()
	res = nm.scan(hosts='192.168.0.0/24', arguments='-O -v')
	#print(res)
	#hosts_list = [(x, nm[x]['state']) for x in nm.all_hosts()]
	#for host,status in hosts_list:
	#	print(host,cpe)
	for x in nm.all_hosts():
		if(nm[x]['status']['state']=="up"):
			print("\n"+x+"\n")
			for keys in nm[x]:
				print(keys,nm[x][keys])
			



if __name__ == '__main__':
	p()