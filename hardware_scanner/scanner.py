import psutil

class Scanner:

	def cpu_scan(self):
		print(psutil.cpu_times())
