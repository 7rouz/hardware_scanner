import os, sys
import re
import time
import platform
import multiprocessing
import ctypes
import subprocess
import cpu

try:
	import _winreg as winreg
except ImportError as err:
	try:
		import winreg
	except ImportError as err:
		pass


class DataSource(object):
	bits = platform.architecture()[0]
	cpu_count = multiprocessing.cpu_count()
	is_windows = platform.system().lower() == 'windows'
	raw_arch_string = platform.machine()

	@staticmethod
	def has_proc_cpuinfo():
		return os.path.exists('/proc/cpuinfo')

	@staticmethod
	def has_dmesg():
		return len(cpu.program_paths('dmesg')) > 0

	@staticmethod
	def has_cpufreq_info():
		return len(cpu.program_paths('cpufreq-info')) > 0

	@staticmethod
	def has_sestatus():
		return len(cpu.program_paths('sestatus')) > 0

	@staticmethod
	def has_sysctl():
		return len(cpu.program_paths('sysctl')) > 0

	@staticmethod
	def has_isainfo():
		return len(cpu.program_paths('isainfo')) > 0

	@staticmethod
	def has_kstat():
		return len(cpu.program_paths('kstat')) > 0

	@staticmethod
	def has_sysinfo():
		return len(cpu.program_paths('sysinfo')) > 0

	@staticmethod
	def cat_proc_cpuinfo():
		return run_and_get_stdout(['cat', '/proc/cpuinfo'])

	@staticmethod
	def cpufreq_info():
		return run_and_get_stdout(['cpufreq-info'])

	@staticmethod
	def sestatus_allow_execheap():
		return run_and_get_stdout(['sestatus', '-b'], ['grep', '-i', '"allow_execheap"'])[1].strip().lower().endswith('on')

	@staticmethod
	def sestatus_allow_execmem():
		return run_and_get_stdout(['sestatus', '-b'], ['grep', '-i', '"allow_execmem"'])[1].strip().lower().endswith('on')

	@staticmethod
	def dmesg_a():
		return run_and_get_stdout(['dmesg', '-a'])

	@staticmethod
	def sysctl_machdep_cpu_hw_cpufrequency():
		return run_and_get_stdout(['sysctl', 'machdep.cpu', 'hw.cpufrequency'])

	@staticmethod
	def isainfo_vb():
		return run_and_get_stdout(['isainfo', '-vb'])

	@staticmethod
	def kstat_m_cpu_info():
		return run_and_get_stdout(['kstat', '-m', 'cpu_info'])

	@staticmethod
	def sysinfo_cpu():
		return run_and_get_stdout(['sysinfo', '-cpu'])

	@staticmethod
	def winreg_processor_brand():
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
		processor_brand = winreg.QueryValueEx(key, "ProcessorNameString")[0]
		winreg.CloseKey(key)
		return processor_brand

	@staticmethod
	def winreg_vendor_id():
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
		vendor_id = winreg.QueryValueEx(key, "VendorIdentifier")[0]
		winreg.CloseKey(key)
		return vendor_id

	@staticmethod
	def winreg_raw_arch_string():
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
		raw_arch_string = winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")[0]
		winreg.CloseKey(key)
		return raw_arch_string

	@staticmethod
	def winreg_hz_actual():
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
		hz_actual = winreg.QueryValueEx(key, "~Mhz")[0]
		winreg.CloseKey(key)
		hz_actual = to_hz_string(hz_actual)
		return hz_actual

	@staticmethod
	def winreg_feature_bits():
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Hardware\Description\System\CentralProcessor\0")
		feature_bits = winreg.QueryValueEx(key, "FeatureSet")[0]
		winreg.CloseKey(key)
		return feature_bits