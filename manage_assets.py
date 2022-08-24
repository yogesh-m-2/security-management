import json
import os

def filter_assets_to_scope(assets):
	if(os.path.exists("Assets_in_scope.csv")):
		for ips in assets["ips"]:
			with open('Assets_in_scope.csv', 'r+') as f:
				content=f.read()
				if(str(ips["ip"]) not in str(content)):
					f.write("%s\n"%ips["ip"])
			f.close()
	else:
		with open('Assets_in_scope.csv', 'w') as f:
			f.write("in scope\n")
			for ips in assets["ips"]:
				f.write("%s\n"%ips["ip"])



def delete_assets_from_scope(assets):
	try:
		with open('Assets_in_scope.csv', 'r') as fr:
			lines = fr.readlines()
		with open('Assets_in_scope.csv', 'w') as fw:
			for line in lines:
				if (line.strip('\n') not in str(assets)):
					fw.write(line)
		print("Deleted")
	except Exception as e:
		print(e)




string={
	"ips": [{
		"ip": "192.168.0.100"
	}, {
		"ip": "192.168.0.101"
	},{
		"ip": "192.168.0.105"
	},{
		"ip": "192.168.0.102"
	}]
}


ds={
	"ips": [{
		"ip": "192.168.0.100"
	}, {
		"ip": "192.168.0.101"
	}]
}

filter_assets_to_scope(string)
delete_assets_from_scope(ds)
