import os, sys
import re
import time
import platform
import multiprocessing
import ctypes
import subprocess
import cpu
from datasource import DataSource

try:
	import _winreg as winreg
except ImportError as err:
	try:
		import winreg
	except ImportError as err:
		pass

class CPUID(object):
	def __init__(self):
		# Figure out if SE Linux is on and in enforcing mode
		self.is_selinux_enforcing = False

		# Just return if the SE Linux Status Tool is not installed
		if not DataSource.has_sestatus():
			return

		# Figure out if we can execute heap and execute memory
		can_selinux_exec_heap = DataSource.sestatus_allow_execheap()
		can_selinux_exec_memory = DataSource.sestatus_allow_execmem()
		self.is_selinux_enforcing = (not can_selinux_exec_heap or not can_selinux_exec_memory)

	def _asm_func(self, restype=None, argtypes=(), byte_code=[]):
		byte_code = bytes.join(b'', byte_code)
		address = None

		if DataSource.is_windows:
			# Allocate a memory segment the size of the byte code, and make it executable
			size = len(byte_code)
			MEM_COMMIT = ctypes.c_ulong(0x1000)
			PAGE_EXECUTE_READWRITE = ctypes.c_ulong(0x40)
			address = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_size_t(size), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
			if not address:
				raise Exception("Failed to VirtualAlloc")
				
			# Copy the byte code into the memory segment
			memmove = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)(ctypes._memmove_addr)
			if memmove(address, byte_code, size) < 0:
				raise Exception("Failed to memmove")
		else:
			# Allocate a memory segment the size of the byte code
			size = len(byte_code)
			address = ctypes.pythonapi.valloc(size)
			if not address:
				raise Exception("Failed to valloc")

			# Mark the memory segment as writeable only
			if not self.is_selinux_enforcing:
				WRITE = 0x2
				if ctypes.pythonapi.mprotect(address, size, WRITE) < 0:
					raise Exception("Failed to mprotect")

			# Copy the byte code into the memory segment
			if ctypes.pythonapi.memmove(address, byte_code, size) < 0:
				raise Exception("Failed to memmove")

			# Mark the memory segment as writeable and executable only
			if not self.is_selinux_enforcing:
				WRITE_EXECUTE = 0x2 | 0x4
				if ctypes.pythonapi.mprotect(address, size, WRITE_EXECUTE) < 0:
					raise Exception("Failed to mprotect")

		# Cast the memory segment into a function
		functype = ctypes.CFUNCTYPE(restype, *argtypes)
		fun = functype(address)
		return fun, address

	def _run_asm(self, *byte_code):
		# Convert the byte code into a function that returns an int
		restype = None
		if DataSource.bits == '64bit':
			restype = ctypes.c_uint64
		else:
			restype = ctypes.c_uint32
		argtypes = ()
		func, address = self._asm_func(restype, argtypes, byte_code)

		# Call the byte code like a function
		retval = func()

		size = ctypes.c_size_t(len(byte_code))

		# Free the function memory segment
		if DataSource.is_windows:
			MEM_RELEASE = ctypes.c_ulong(0x8000)
			ctypes.windll.kernel32.VirtualFree(address, size, MEM_RELEASE)
		else:
			# Remove the executable tag on the memory
			READ_WRITE = 0x1 | 0x2
			if ctypes.pythonapi.mprotect(address, size, READ_WRITE) < 0:
				raise Exception("Failed to mprotect")

			ctypes.pythonapi.free(address)

		return retval

	# FIXME: We should not have to use different instructions to
	# set eax to 0 or 1, on 32bit and 64bit machines.
	def _zero_eax(self):
		if DataSource.bits == '64bit':
			return (
				b"\x66\xB8\x00\x00" # mov eax,0x0"
			)
		else:
			return (
				b"\x31\xC0"         # xor ax,ax
			)

	def _one_eax(self):
		if DataSource.bits == '64bit':
			return (
				b"\x66\xB8\x01\x00" # mov eax,0x1"
			)
		else:
			return (
				b"\x31\xC0"         # xor ax,ax
				b"\x40"             # inc ax
			)

	# http://en.wikipedia.org/wiki/CPUID#EAX.3D0:_Get_vendor_ID
	def get_vendor_id(self):
		# EBX
		ebx = self._run_asm(
			self._zero_eax(),
			b"\x0F\xA2"         # cpuid
			b"\x89\xD8"         # mov ax,bx
			b"\xC3"             # ret
		)

		# ECX
		ecx = self._run_asm(
			self._zero_eax(),
			b"\x0f\xa2"         # cpuid
			b"\x89\xC8"         # mov ax,cx
			b"\xC3"             # ret
		)

		# EDX
		edx = self._run_asm(
			self._zero_eax(),
			b"\x0f\xa2"         # cpuid
			b"\x89\xD0"         # mov ax,dx
			b"\xC3"             # ret
		)

		# Each 4bits is a ascii letter in the name
		vendor_id = []
		for reg in [ebx, edx, ecx]:
			for n in [0, 8, 16, 24]:
				vendor_id.append(chr((reg >> n) & 0xFF))
		vendor_id = ''.join(vendor_id)

		return vendor_id

	# http://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits
	def get_info(self):
		# EAX
		eax = self._run_asm(
			self._one_eax(),
			b"\x0f\xa2"         # cpuid
			b"\xC3"             # ret
		)

		# Get the CPU info
		stepping = (eax >> 0) & 0xF # 4 bits
		model = (eax >> 4) & 0xF # 4 bits
		family = (eax >> 8) & 0xF # 4 bits
		processor_type = (eax >> 12) & 0x3 # 2 bits
		extended_model = (eax >> 16) & 0xF # 4 bits
		extended_family = (eax >> 20) & 0xFF # 8 bits

		return {
			'stepping' : stepping,
			'model' : model,
			'family' : family,
			'processor_type' : processor_type,
			'extended_model' : extended_model,
			'extended_family' : extended_family
		}

	def get_max_extension_support(self):
		# Check for extension support
		max_extension_support = self._run_asm(
			b"\xB8\x00\x00\x00\x80" # mov ax,0x80000000
			b"\x0f\xa2"             # cpuid
			b"\xC3"                 # ret
		)

		return max_extension_support

	# http://en.wikipedia.org/wiki/CPUID#EAX.3D1:_Processor_Info_and_Feature_Bits
	def get_flags(self, max_extension_support):
		# EDX
		edx = self._run_asm(
			self._one_eax(),
			b"\x0f\xa2"         # cpuid
			b"\x89\xD0"         # mov ax,dx
			b"\xC3"             # ret
		)

		# ECX
		ecx = self._run_asm(
			self._one_eax(),
			b"\x0f\xa2"         # cpuid
			b"\x89\xC8"         # mov ax,cx
			b"\xC3"             # ret
		)

		# Get the CPU flags
		flags = {
			'fpu' : cpu.is_bit_set(edx, 0),
			'vme' : cpu.is_bit_set(edx, 1),
			'de' : cpu.is_bit_set(edx, 2),
			'pse' : cpu.is_bit_set(edx, 3),
			'tsc' : cpu.is_bit_set(edx, 4),
			'msr' : cpu.is_bit_set(edx, 5),
			'pae' : cpu.is_bit_set(edx, 6),
			'mce' : cpu.is_bit_set(edx, 7),
			'cx8' : cpu.is_bit_set(edx, 8),
			'apic' : cpu.is_bit_set(edx, 9),
			#'reserved1' : cpu.is_bit_set(edx, 10),
			'sep' : cpu.is_bit_set(edx, 11),
			'mtrr' : cpu.is_bit_set(edx, 12),
			'pge' : cpu.is_bit_set(edx, 13),
			'mca' : cpu.is_bit_set(edx, 14),
			'cmov' : cpu.is_bit_set(edx, 15),
			'pat' : cpu.is_bit_set(edx, 16),
			'pse36' : cpu.is_bit_set(edx, 17),
			'pn' : cpu.is_bit_set(edx, 18),
			'clflush' : cpu.is_bit_set(edx, 19),
			#'reserved2' : is_bit_set(edx, 20),
			'dts' : cpu.is_bit_set(edx, 21),
			'acpi' : cpu.is_bit_set(edx, 22),
			'mmx' : cpu.is_bit_set(edx, 23),
			'fxsr' : cpu.is_bit_set(edx, 24),
			'sse' : cpu.is_bit_set(edx, 25),
			'sse2' : cpu.is_bit_set(edx, 26),
			'ss' : cpu.is_bit_set(edx, 27),
			'ht' : cpu.is_bit_set(edx, 28),
			'tm' : cpu.is_bit_set(edx, 29),
			'ia64' : cpu.is_bit_set(edx, 30),
			'pbe' : cpu.is_bit_set(edx, 31),

			'pni' : cpu.is_bit_set(ecx, 0),
			'pclmulqdq' : cpu.is_bit_set(ecx, 1),
			'dtes64' : cpu.is_bit_set(ecx, 2),
			'monitor' : cpu.is_bit_set(ecx, 3),
			'ds_cpl' : cpu.is_bit_set(ecx, 4),
			'vmx' : cpu.is_bit_set(ecx, 5),
			'smx' : cpu.is_bit_set(ecx, 6),
			'est' : cpu.is_bit_set(ecx, 7),
			'tm2' : cpu.is_bit_set(ecx, 8),
			'ssse3' : cpu.is_bit_set(ecx, 9),
			'cid' : cpu.is_bit_set(ecx, 10),
			#'reserved3' : cpu.is_bit_set(ecx, 11),
			'fma' : cpu.is_bit_set(ecx, 12),
			'cx16' : cpu.is_bit_set(ecx, 13),
			'xtpr' : cpu.is_bit_set(ecx, 14),
			'pdcm' : cpu.is_bit_set(ecx, 15),
			#'reserved4' : cpu.is_bit_set(ecx, 16),
			'pcid' : cpu.is_bit_set(ecx, 17),
			'dca' : cpu.is_bit_set(ecx, 18),
			'sse4_1' : cpu.is_bit_set(ecx, 19),
			'sse4_2' : cpu.is_bit_set(ecx, 20),
			'x2apic' : cpu.is_bit_set(ecx, 21),
			'movbe' : cpu.is_bit_set(ecx, 22),
			'popcnt' : cpu.is_bit_set(ecx, 23),
			'tscdeadline' : cpu.is_bit_set(ecx, 24),
			'aes' : cpu.is_bit_set(ecx, 25),
			'xsave' : cpu.is_bit_set(ecx, 26),
			'osxsave' : cpu.is_bit_set(ecx, 27),
			'avx' : cpu.is_bit_set(ecx, 28),
			'f16c' : cpu.is_bit_set(ecx, 29),
			'rdrnd' : cpu.is_bit_set(ecx, 30),
			'hypervisor' : cpu.is_bit_set(ecx, 31)
		}

		# Get a list of only the flags that are true
		flags = [k for k, v in flags.items() if v]

		# Get the Extended CPU flags
		extended_flags = {}
		if max_extension_support >= 0x80000001:
			# EBX
			ebx = self._run_asm(
				b"\xB8\x01\x00\x00\x80" # mov ax,0x80000001
				b"\x0f\xa2"         # cpuid
				b"\x89\xD8"         # mov ax,bx
				b"\xC3"             # ret
			)

			# ECX
			ecx = self._run_asm(
				b"\xB8\x01\x00\x00\x80" # mov ax,0x80000001
				b"\x0f\xa2"         # cpuid
				b"\x89\xC8"         # mov ax,cx
				b"\xC3"             # ret
			)

			# Get the extended CPU flags
			extended_flags = {
				'fpu' : cpu.is_bit_set(ebx, 0),
				'vme' : cpu.is_bit_set(ebx, 1),
				'de' : cpu.is_bit_set(ebx, 2),
				'pse' : cpu.is_bit_set(ebx, 3),
				'tsc' : cpu.is_bit_set(ebx, 4),
				'msr' : cpu.is_bit_set(ebx, 5),
				'pae' : cpu.is_bit_set(ebx, 6),
				'mce' : cpu.is_bit_set(ebx, 7),
				'cx8' : cpu.is_bit_set(ebx, 8),
				'apic' : cpu.is_bit_set(ebx, 9),
				#'reserved' : cpu.is_bit_set(ebx, 10),
				'syscall' : cpu.is_bit_set(ebx, 11),
				'mtrr' : cpu.is_bit_set(ebx, 12),
				'pge' : cpu.is_bit_set(ebx, 13),
				'mca' : cpu.is_bit_set(ebx, 14),
				'cmov' : cpu.is_bit_set(ebx, 15),
				'pat' : cpu.is_bit_set(ebx, 16),
				'pse36' : cpu.is_bit_set(ebx, 17),
				#'reserved' : cpu.is_bit_set(ebx, 18),
				'mp' : cpu.is_bit_set(ebx, 19),
				'nx' : cpu.is_bit_set(ebx, 20),
				#'reserved' : cpu.is_bit_set(ebx, 21),
				'mmxext' : cpu.is_bit_set(ebx, 22),
				'mmx' : cpu.is_bit_set(ebx, 23),
				'fxsr' : cpu.is_bit_set(ebx, 24),
				'fxsr_opt' : cpu.is_bit_set(ebx, 25),
				'pdpe1gp' : cpu.is_bit_set(ebx, 26),
				'rdtscp' : cpu.is_bit_set(ebx, 27),
				#'reserved' : cpu.is_bit_set(ebx, 28),
				'lm' : cpu.is_bit_set(ebx, 29),
				'3dnowext' : cpu.is_bit_set(ebx, 30),
				'3dnow' : cpu.is_bit_set(ebx, 31),

				'lahf_lm' : cpu.is_bit_set(ecx, 0),
				'cmp_legacy' : cpu.is_bit_set(ecx, 1),
				'svm' : cpu.is_bit_set(ecx, 2),
				'extapic' : cpu.is_bit_set(ecx, 3),
				'cr8_legacy' : cpu.is_bit_set(ecx, 4),
				'abm' : cpu.is_bit_set(ecx, 5),
				'sse4a' : cpu.is_bit_set(ecx, 6),
				'misalignsse' : cpu.is_bit_set(ecx, 7),
				'3dnowprefetch' : cpu.is_bit_set(ecx, 8),
				'osvw' : cpu.is_bit_set(ecx, 9),
				'ibs' : cpu.is_bit_set(ecx, 10),
				'xop' : cpu.is_bit_set(ecx, 11),
				'skinit' : cpu.is_bit_set(ecx, 12),
				'wdt' : cpu.is_bit_set(ecx, 13),
				#'reserved' : cpu.is_bit_set(ecx, 14),
				'lwp' : cpu.is_bit_set(ecx, 15),
				'fma4' : cpu.is_bit_set(ecx, 16),
				'tce' : cpu.is_bit_set(ecx, 17),
				#'reserved' : cpu.is_bit_set(ecx, 18),
				'nodeid_msr' : cpu.is_bit_set(ecx, 19),
				#'reserved' : cpu.is_bit_set(ecx, 20),
				'tbm' : cpu.is_bit_set(ecx, 21),
				'topoext' : cpu.is_bit_set(ecx, 22),
				'perfctr_core' : cpu.is_bit_set(ecx, 23),
				'perfctr_nb' : cpu.is_bit_set(ecx, 24),
				#'reserved' : cpu.is_bit_set(ecx, 25),
				'dbx' : cpu.is_bit_set(ecx, 26),
				'perftsc' : cpu.is_bit_set(ecx, 27),
				'pci_l2i' : cpu.is_bit_set(ecx, 28),
				#'reserved' : cpu.is_bit_set(ecx, 29),
				#'reserved' : cpu.is_bit_set(ecx, 30),
				#'reserved' : cpu.is_bit_set(ecx, 31)
			}
		# Get a list of only the flags that are true
		extended_flags = [k for k, v in extended_flags.items() if v]
		flags += extended_flags

		flags.sort()
		return flags

	def get_processor_brand(self, max_extension_support):
		processor_brand = ""

		# Processor brand string
		if max_extension_support >= 0x80000004:
			instructions = [
				b"\xB8\x02\x00\x00\x80", # mov ax,0x80000002
				b"\xB8\x03\x00\x00\x80", # mov ax,0x80000003
				b"\xB8\x04\x00\x00\x80"  # mov ax,0x80000004
			]
			for instruction in instructions:
				# EAX
				eax = self._run_asm(
					instruction,  # mov ax,0x8000000?
					b"\x0f\xa2"   # cpuid
					b"\x89\xC0"   # mov ax,ax
					b"\xC3"       # ret
				)

				# EBX
				ebx = self._run_asm(
					instruction,  # mov ax,0x8000000?
					b"\x0f\xa2"   # cpuid
					b"\x89\xD8"   # mov ax,bx
					b"\xC3"       # ret
				)

				# ECX
				ecx = self._run_asm(
					instruction,  # mov ax,0x8000000?
					b"\x0f\xa2"   # cpuid
					b"\x89\xC8"   # mov ax,cx
					b"\xC3"       # ret
				)

				# EDX
				edx = self._run_asm(
					instruction,  # mov ax,0x8000000?
					b"\x0f\xa2"   # cpuid
					b"\x89\xD0"   # mov ax,dx
					b"\xC3"       # ret
				)

				# Combine each of the 4 bytes in each register into the string
				for reg in [eax, ebx, ecx, edx]:
					for n in [0, 8, 16, 24]:
						processor_brand += chr((reg >> n) & 0xFF)

		# Strip off any trailing NULL terminators and white space
		processor_brand = processor_brand.strip("\0").strip()

		return processor_brand

	def get_cache(self, max_extension_support):
		cache_info = {}

		# Just return if the cache feature is not supported
		if max_extension_support < 0x80000006:
			return cache_info

		# ECX
		ecx = self._run_asm(
			b"\xB8\x06\x00\x00\x80"  # mov ax,0x80000006
			b"\x0f\xa2"              # cpuid
			b"\x89\xC8"              # mov ax,cx
			b"\xC3"                   # ret
		)

		cache_info = {
			'size_kb' : ecx & 0xFF,
			'line_size_b' : (ecx >> 12) & 0xF,
			'associativity' : (ecx >> 16) & 0xFFFF
		}

		return cache_info

	def get_ticks(self):
		retval = None

		if DataSource.bits == '32bit':
			# Works on x86_32
			restype = None
			argtypes = (ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint))
			get_ticks_x86_32, address = self._asm_func(restype, argtypes,
				[
				b"\x55",         # push bp
				b"\x89\xE5",     # mov bp,sp
				b"\x31\xC0",     # xor ax,ax
				b"\x0F\xA2",     # cpuid
				b"\x0F\x31",     # rdtsc
				b"\x8B\x5D\x08", # mov bx,[di+0x8]
				b"\x8B\x4D\x0C", # mov cx,[di+0xc]
				b"\x89\x13",     # mov [bp+di],dx
				b"\x89\x01",     # mov [bx+di],ax
				b"\x5D",         # pop bp
				b"\xC3"          # ret
				]
			)

			high = ctypes.c_uint32(0)
			low = ctypes.c_uint32(0)

			get_ticks_x86_32(ctypes.byref(high), ctypes.byref(low))
			retval = ((high.value << 32) & 0xFFFFFFFF00000000) | low.value
		elif DataSource.bits == '64bit':
			# Works on x86_64
			restype = ctypes.c_uint64
			argtypes = ()
			get_ticks_x86_64, address = self._asm_func(restype, argtypes,
				[
				b"\x48",         # dec ax
				b"\x31\xC0",     # xor ax,ax
				b"\x0F\xA2",     # cpuid
				b"\x0F\x31",     # rdtsc
				b"\x48",         # dec ax
				b"\xC1\xE2\x20", # shl dx,byte 0x20
				b"\x48",         # dec ax
				b"\x09\xD0",     # or ax,dx
				b"\xC3",         # ret
				]
			)
			retval = get_ticks_x86_64()

		return retval

	def get_raw_hz(self):
		start = self.get_ticks()

		time.sleep(1)

		end = self.get_ticks()

		ticks = (end - start)

		return ticks
