import psutil
import json

class Scanner:

	def cpu_scan(self):
		print("This computer has %d CPUs" % psutil.cpu_count())
		print(psutil.cpu_times())
		print("CPU in percent :")
		print(psutil.cpu_times_percent())

	def memory_scan(self):
		print("Memory caracteristics of this computer are:")
		print("RAM ")
		print(psutil.virtual_memory())
		print("SWAP ")
		print(psutil.swap_memory())

	def network_scan(self):
		print("Network interfaces and there states")
		net_list = psutil.net_if_addrs()
		for n in net_list:
			print n
			print(psutil.net_if_addrs()[str(n)])
		net_add_list = psutil.net_if_addrs()
		print("Network interfaces adresses")
		for addr in net_list:
			print addr
			print(psutil.net_if_addrs()[str(addr)])

	def disk_scan(self):
		print ("Disk partitionning")
		for d in psutil.disk_partitions(): 
			print(d)
		print("Disk usage")
		print(psutil.disk_usage('/'))

	def users_scan(self):
		print("this operating system users are:")
		print(psutil.users())