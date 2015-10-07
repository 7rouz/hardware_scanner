import os, sys
import re
import time
import platform
import multiprocessing
import ctypes
import subprocess
from cpuid import CPUID
from datasource import DataSource

try:
	import _winreg as winreg
except ImportError as err:
	try:
		import winreg
	except ImportError as err:
		pass

PY2 = sys.version_info[0] == 2


def run_and_get_stdout(command, pipe_command=None):
	if not pipe_command:
		p1 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output = p1.communicate()[0]
		if not PY2:
			output = output.decode(encoding='UTF-8')
		return p1.returncode, output
	else:
		p1 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p2 = subprocess.Popen(pipe_command, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		p1.stdout.close()
		output = p2.communicate()[0]
		if not PY2:
			output = output.decode(encoding='UTF-8')
		return p2.returncode, output


def program_paths(program_name):
	paths = []
	exts = filter(None, os.environ.get('PATHEXT', '').split(os.pathsep))
	path = os.environ['PATH']
	for p in os.environ['PATH'].split(os.pathsep):
		p = os.path.join(p, program_name)
		if os.access(p, os.X_OK):
			paths.append(p)
		for e in exts:
			pext = p + e
			if os.access(pext, os.X_OK):
				paths.append(pext)
	return paths

def _get_field(raw_string, convert_to, default_value, *field_names):
	retval = None

	for field_name in field_names:
		if field_name in raw_string:
			raw_field = raw_string.split(field_name)[1] # Everything after the field name
			raw_field = raw_field.split(':')[1] # Everything after the :
			raw_field = raw_field.split('\n')[0] # Everything before the \n
			raw_field = raw_field.strip() # Strip any extra white space
			retval = raw_field
			break

	# Convert the return value
	if retval and convert_to:
		try:
			retval = convert_to(retval)
		except:
			retval = default_value

	# Return the default if there is no return value
	if retval is None:
		retval = default_value

	return retval

def _get_hz_string_from_brand(processor_brand):
	# Just return 0 if the processor brand does not have the Hz
	if not 'hz' in processor_brand.lower():
		return (1, '0.0')

	hz_brand = processor_brand.lower()
	scale = 1

	if hz_brand.endswith('mhz'):
		scale = 6
	elif hz_brand.endswith('ghz'):
		scale = 9
	if '@' in hz_brand:
		hz_brand = hz_brand.split('@')[1]
	else:
		hz_brand = hz_brand.rsplit(None, 1)[1]

	hz_brand = hz_brand.rstrip('mhz').rstrip('ghz').strip()
	hz_brand = to_hz_string(hz_brand)

	return (scale, hz_brand)

def _get_hz_string_from_beagle_bone():
	scale, hz_brand = 1, '0.0'

	if not DataSource.has_cpufreq_info():
		return scale, hz_brand

	returncode, output = DataSource.cpufreq_info()
	if returncode != 0:
		return (scale, hz_brand)

	hz_brand = output.split('current CPU frequency is')[1].split('.')[0].lower()

	if hz_brand.endswith('mhz'):
		scale = 6
	elif hz_brand.endswith('ghz'):
		scale = 9
	hz_brand = hz_brand.rstrip('mhz').rstrip('ghz').strip()
	hz_brand = to_hz_string(hz_brand)

	return (scale, hz_brand)

def to_friendly_hz(ticks, scale):
	# Get the raw Hz as a string
	left, right = to_raw_hz(ticks, scale)
	ticks = '{0}.{1}'.format(left, right)

	# Get the location of the dot, and remove said dot
	dot_index = ticks.index('.')
	ticks = ticks.replace('.', '')

	# Get the Hz symbol and scale
	symbol = "Hz"
	scale = 0
	if dot_index > 9:
		symbol = "GHz"
		scale = 9
	elif dot_index > 6:
		symbol = "MHz"
		scale = 6
	elif dot_index > 3:
		symbol = "KHz"
		scale = 3

	# Get the Hz with the dot at the new scaled point
	ticks = '{0}.{1}'.format(ticks[:-scale-1], ticks[-scale-1:])

	# Format the ticks to have 4 numbers after the decimal
	# and remove any superfluous zeroes.
	ticks = '{0:.4f} {1}'.format(float(ticks), symbol)
	ticks = ticks.rstrip('0')

	return ticks

def to_raw_hz(ticks, scale):
	# Scale the numbers
	ticks = ticks.lstrip('0')
	old_index = ticks.index('.')
	ticks = ticks.replace('.', '')
	ticks = ticks.ljust(scale + old_index+1, '0')
	new_index = old_index + scale
	ticks = '{0}.{1}'.format(ticks[:new_index], ticks[new_index:])
	left, right = ticks.split('.')
	left, right = int(left), int(right)
	return (left, right)

def to_hz_string(ticks):
	# Convert to string
	ticks = '{0}'.format(ticks)

	# Add decimal if missing
	if '.' not in ticks:
		ticks = '{0}.0'.format(ticks)

	# Remove trailing zeros
	ticks = ticks.rstrip('0')

	# Add one trailing zero for empty right side
	if ticks.endswith('.'):
		ticks = '{0}0'.format(ticks)

	return ticks

def parse_arch(raw_arch_string):
	arch, bits = None, None
	raw_arch_string = raw_arch_string.lower()

	# X86
	if re.match('^i\d86$|^x86$|^x86_32$|^i86pc$|^ia32$|^ia-32$|^bepc$', raw_arch_string):
		arch = 'X86_32'
		bits = 32
	elif re.match('^x64$|^x86_64$|^x86_64t$|^i686-64$|^amd64$|^ia64$|^ia-64$', raw_arch_string):
		arch = 'X86_64'
		bits = 64
	# ARM
	elif re.match('^armv8-a$', raw_arch_string):
		arch = 'ARM_8'
		bits = 64
	elif re.match('^armv7$|^armv7[a-z]$|^armv7-[a-z]$', raw_arch_string):
		arch = 'ARM_7'
		bits = 32
	elif re.match('^armv8$|^armv8[a-z]$|^armv8-[a-z]$', raw_arch_string):
		arch = 'ARM_8'
		bits = 32
	# PPC
	elif re.match('^ppc32$|^prep$|^pmac$|^powermac$', raw_arch_string):
		arch = 'PPC_32'
		bits = 32
	elif re.match('^powerpc$|^ppc64$', raw_arch_string):
		arch = 'PPC_64'
		bits = 64
	# SPARC
	elif re.match('^sparc32$|^sparc$', raw_arch_string):
		arch = 'SPARC_32'
		bits = 32
	elif re.match('^sparc64$|^sun4u$|^sun4v$', raw_arch_string):
		arch = 'SPARC_64'
		bits = 64

	return (arch, bits)

def is_bit_set(reg, bit):
	mask = 1 << bit
	is_set = reg & mask > 0
	return is_set




def get_cpu_info_from_cpuid():
	'''
	Returns the CPU info gathered by querying the X86 cpuid register.
	Returns None of non X86 cpus.
	Returns None if SELinux is in enforcing mode.
	'''
	# Get the CPU arch and bits
	arch, bits = parse_arch(DataSource.raw_arch_string)

	# Return none if this is not an X86 CPU
	if not arch in ['X86_32', 'X86_64']:
		return None

	# Return none if SE Linux is in enforcing mode
	cpuid = CPUID()
	if cpuid.is_selinux_enforcing:
		return None

	# Get the cpu info from the CPUID register
	max_extension_support = cpuid.get_max_extension_support()
	cache_info = cpuid.get_cache(max_extension_support)
	info = cpuid.get_info()

	processor_brand = cpuid.get_processor_brand(max_extension_support)

	# Get the Hz and scale
	hz_actual = cpuid.get_raw_hz()
	hz_actual = to_hz_string(hz_actual)

	# Get the Hz and scale
	scale, hz_advertised = _get_hz_string_from_brand(processor_brand)

	return {
	'vendor_id' : cpuid.get_vendor_id(),
	'hardware' : '',
	'brand' : processor_brand,

	'hz_advertised' : to_friendly_hz(hz_advertised, scale),
	'hz_actual' : to_friendly_hz(hz_actual, 6),
	'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
	'hz_actual_raw' : to_raw_hz(hz_actual, 6),

	'arch' : arch,
	'bits' : bits,
	'count' : DataSource.cpu_count,
	'raw_arch_string' : DataSource.raw_arch_string,

	'l2_cache_size' : cache_info['size_kb'],
	'l2_cache_line_size' : cache_info['line_size_b'],
	'l2_cache_associativity' : hex(cache_info['associativity']),

	'stepping' : info['stepping'],
	'model' : info['model'],
	'family' : info['family'],
	'processor_type' : info['processor_type'],
	'extended_model' : info['extended_model'],
	'extended_family' : info['extended_family'],
	'flags' : cpuid.get_flags(max_extension_support)
	}

def get_cpu_info_from_proc_cpuinfo():
	'''
	Returns the CPU info gathered from /proc/cpuinfo. Will return None if
	/proc/cpuinfo is not found.
	'''
	try:
		# Just return None if there is no cpuinfo
		if not DataSource.has_proc_cpuinfo():
			return None

		returncode, output = DataSource.cat_proc_cpuinfo()
		if returncode != 0:
			return None

		# Various fields
		vendor_id = _get_field(output, None, '', 'vendor_id', 'vendor id', 'vendor')
		processor_brand = _get_field(output, None, None, 'model name','cpu')
		cache_size = _get_field(output, None, '', 'cache size')
		stepping = _get_field(output, int, 0, 'stepping')
		model = _get_field(output, int, 0, 'model')
		family = _get_field(output, int, 0, 'cpu family')
		hardware = _get_field(output, None, '', 'Hardware')

		# Flags
		flags = _get_field(output, None, None, 'flags', 'Features').split()
		flags.sort()

		# Convert from MHz string to Hz
		hz_actual = _get_field(output, None, '', 'cpu MHz', 'cpu speed', 'clock')
		hz_actual = hz_actual.lower().rstrip('mhz').strip()
		hz_actual = to_hz_string(hz_actual)

		# Convert from GHz/MHz string to Hz
		scale, hz_advertised = _get_hz_string_from_brand(processor_brand)

		# Try getting the Hz for a BeagleBone
		if hz_advertised == '0.0':
			scale, hz_advertised = _get_hz_string_from_beagle_bone()
			hz_actual = hz_advertised

		# Get the CPU arch and bits
		arch, bits = parse_arch(DataSource.raw_arch_string)

		return {
		'vendor_id' : vendor_id,
		'hardware' : hardware,
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, 6),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, 6),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : DataSource.raw_arch_string,

		'l2_cache_size' : cache_size,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : stepping,
		'model' : model,
		'family' : family,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info_from_dmesg():
	'''
	Returns the CPU info gathered from dmesg. Will return None if
	dmesg is not found or does not have the desired info.
	'''
	try:
		# Just return None if there is no dmesg
		if not DataSource.has_dmesg():
			return None

		# If dmesg fails return None
		returncode, output = DataSource.dmesg_a()
		if output == None or returncode != 0:
			return None

		# Processor Brand
		long_brand = output.split('CPU: ')[1].split('\n')[0]
		processor_brand = long_brand.rsplit('(', 1)[0]
		processor_brand = processor_brand.strip()

		# Hz
		scale = 0
		hz_actual = long_brand.rsplit('(', 1)[1].split(' ')[0].lower()
		if hz_actual.endswith('mhz'):
			scale = 6
		elif hz_actual.endswith('ghz'):
			scale = 9
		hz_actual = hz_actual.split('-')[0]
		hz_actual = to_hz_string(hz_actual)

		# Various fields
		fields = output.split('CPU: ')[1].split('\n')[1].split('\n')[0].strip().split('  ')
		vendor_id = None
		stepping = None
		model = None
		family = None
		for field in fields:
			name, value = field.split(' = ')
			name = name.lower()
			if name == 'origin':
				vendor_id = value.strip('"')
			elif name == 'stepping':
				stepping = int(value)
			elif name == 'model':
				model = int(value, 16)
			elif name == 'family':
				family = int(value, 16)

		# Flags
		flag_lines = []
		for category in ['  Features=', '  Features2=', '  AMD Features=', '  AMD Features2=']:
			if category in output:
				flag_lines.append(output.split(category)[1].split('\n')[0])

		flags = []
		for line in flag_lines:
			line = line.split('<')[1].split('>')[0].lower()
			for flag in line.split(','):
				flags.append(flag)
		flags.sort()

		# Convert from GHz/MHz string to Hz
		scale, hz_advertised = _get_hz_string_from_brand(processor_brand)

		# Get the CPU arch and bits
		arch, bits = parse_arch(DataSource.raw_arch_string)

		return {
		'vendor_id' : vendor_id,
		'hardware' : '',
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, 6),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, 6),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : DataSource.raw_arch_string,

		'l2_cache_size' : 0,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : stepping,
		'model' : model,
		'family' : family,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info_from_sysctl():
	'''
	Returns the CPU info gathered from sysctl. Will return None if
	sysctl is not found.
	'''
	try:
		# Just return None if there is no sysctl
		if not DataSource.has_sysctl():
			return None

		# If sysctl fails return None
		returncode, output = DataSource.sysctl_machdep_cpu_hw_cpufrequency()
		if output == None or returncode != 0:
			return None

		# Various fields
		vendor_id = _get_field(output, None, None, 'machdep.cpu.vendor')
		processor_brand = _get_field(output, None, None, 'machdep.cpu.brand_string')
		cache_size = _get_field(output, None, None, 'machdep.cpu.cache.size')
		stepping = _get_field(output, int, 0, 'machdep.cpu.stepping')
		model = _get_field(output, int, 0, 'machdep.cpu.model')
		family = _get_field(output, int, 0, 'machdep.cpu.family')

		# Flags
		flags = _get_field(output, None, None, 'machdep.cpu.features').lower().split()
		flags.sort()

		# Convert from GHz/MHz string to Hz
		scale, hz_advertised = _get_hz_string_from_brand(processor_brand)
		hz_actual = _get_field(output, None, None, 'hw.cpufrequency')
		hz_actual = to_hz_string(hz_actual)

		# Get the CPU arch and bits
		arch, bits = parse_arch(DataSource.raw_arch_string)

		return {
		'vendor_id' : vendor_id,
		'hardware' : '',
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, 0),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, 0),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : DataSource.raw_arch_string,

		'l2_cache_size' : cache_size,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : stepping,
		'model' : model,
		'family' : family,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info_from_sysinfo():
	'''
	Returns the CPU info gathered from sysinfo. Will return None if
	sysinfo is not found.
	'''
	try:
		# Just return None if there is no sysinfo
		if not DataSource.has_sysinfo():
			return None

		# If sysinfo fails return None
		returncode, output = DataSource.sysinfo_cpu()
		if output == None or returncode != 0:
			return None

		# Various fields
		vendor_id = '' #_get_field(output, None, None, 'CPU #0: ')
		processor_brand = output.split('CPU #0: "')[1].split('"\n')[0]
		cache_size = '' #_get_field(output, None, None, 'machdep.cpu.cache.size')
		stepping = int(output.split(', stepping ')[1].split(',')[0].strip())
		model = int(output.split(', model ')[1].split(',')[0].strip())
		family = int(output.split(', family ')[1].split(',')[0].strip())

		# Flags
		flags = []
		for line in output.split('\n'):
			if line.startswith('\t\t'):
				for flag in line.strip().lower().split():
					flags.append(flag)
		flags.sort()

		# Convert from GHz/MHz string to Hz
		scale, hz_advertised = _get_hz_string_from_brand(processor_brand)
		hz_actual = hz_advertised

		# Get the CPU arch and bits
		arch, bits = parse_arch(DataSource.raw_arch_string)

		return {
		'vendor_id' : vendor_id,
		'hardware' : '',
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, scale),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, scale),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : DataSource.raw_arch_string,

		'l2_cache_size' : cache_size,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : stepping,
		'model' : model,
		'family' : family,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info_from_registry():
	'''
	FIXME: Is missing many of the newer CPU flags like sse3
	Returns the CPU info gathered from the Windows Registry. Will return None if
	not on Windows.
	'''
	try:
		# Just return None if not on Windows
		if not DataSource.is_windows:
			return None

		# Get the CPU name
		processor_brand = DataSource.winreg_processor_brand()

		# Get the CPU vendor id
		vendor_id = DataSource.winreg_vendor_id()

		# Get the CPU arch and bits
		raw_arch_string = DataSource.winreg_raw_arch_string()
		arch, bits = parse_arch(raw_arch_string)

		# Get the actual CPU Hz
		hz_actual = DataSource.winreg_hz_actual()
		hz_actual = to_hz_string(hz_actual)

		# Get the advertised CPU Hz
		scale, hz_advertised = _get_hz_string_from_brand(processor_brand)

		# Get the CPU features
		feature_bits = DataSource.winreg_feature_bits()

		def is_set(bit):
			mask = 0x80000000 >> bit
			retval = mask & feature_bits > 0
			return retval

		# http://en.wikipedia.org/wiki/CPUID
		# http://unix.stackexchange.com/questions/43539/what-do-the-flags-in-proc-cpuinfo-mean
		# http://www.lohninger.com/helpcsuite/public_constants_cpuid.htm
		flags = {
			'fpu' : is_set(0), # Floating Point Unit
			'vme' : is_set(1), # V86 Mode Extensions
			'de' : is_set(2), # Debug Extensions - I/O breakpoints supported
			'pse' : is_set(3), # Page Size Extensions (4 MB pages supported)
			'tsc' : is_set(4), # Time Stamp Counter and RDTSC instruction are available
			'msr' : is_set(5), # Model Specific Registers
			'pae' : is_set(6), # Physical Address Extensions (36 bit address, 2MB pages)
			'mce' : is_set(7), # Machine Check Exception supported
			'cx8' : is_set(8), # Compare Exchange Eight Byte instruction available
			'apic' : is_set(9), # Local APIC present (multiprocessor operation support)
			'sepamd' : is_set(10), # Fast system calls (AMD only)
			'sep' : is_set(11), # Fast system calls
			'mtrr' : is_set(12), # Memory Type Range Registers
			'pge' : is_set(13), # Page Global Enable
			'mca' : is_set(14), # Machine Check Architecture
			'cmov' : is_set(15), # Conditional MOVe instructions
			'pat' : is_set(16), # Page Attribute Table
			'pse36' : is_set(17), # 36 bit Page Size Extensions
			'serial' : is_set(18), # Processor Serial Number
			'clflush' : is_set(19), # Cache Flush
			#'reserved1' : is_set(20), # reserved
			'dts' : is_set(21), # Debug Trace Store
			'acpi' : is_set(22), # ACPI support
			'mmx' : is_set(23), # MultiMedia Extensions
			'fxsr' : is_set(24), # FXSAVE and FXRSTOR instructions
			'sse' : is_set(25), # SSE instructions
			'sse2' : is_set(26), # SSE2 (WNI) instructions
			'ss' : is_set(27), # self snoop
			#'reserved2' : is_set(28), # reserved
			'tm' : is_set(29), # Automatic clock control
			'ia64' : is_set(30), # IA64 instructions
			'3dnow' : is_set(31) # 3DNow! instructions available
		}

		# Get a list of only the flags that are true
		flags = [k for k, v in flags.items() if v]
		flags.sort()

		return {
		'vendor_id' : vendor_id,
		'hardware' : '',
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, 6),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, 6),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : raw_arch_string,

		'l2_cache_size' : 0,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : 0,
		'model' : 0,
		'family' : 0,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info_from_kstat():
	'''
	Returns the CPU info gathered from isainfo and kstat. Will 
	return None if isainfo or kstat are not found.
	'''
	try:
		# Just return None if there is no isainfo or kstat
		if not DataSource.has_isainfo() or not DataSource.has_kstat():
			return None

		# If isainfo fails return None
		returncode, flag_output = DataSource.isainfo_vb()
		if flag_output == None or returncode != 0:
			return None

		# If kstat fails return None
		returncode, kstat = DataSource.kstat_m_cpu_info()
		if kstat == None or returncode != 0:
			return None

		# Various fields
		vendor_id = kstat.split('\tvendor_id ')[1].split('\n')[0].strip()
		processor_brand = kstat.split('\tbrand ')[1].split('\n')[0].strip()
		cache_size = 0
		stepping = int(kstat.split('\tstepping ')[1].split('\n')[0].strip())
		model = int(kstat.split('\tmodel ')[1].split('\n')[0].strip())
		family = int(kstat.split('\tfamily ')[1].split('\n')[0].strip())

		# Flags
		flags = flag_output.strip().split('\n')[-1].strip().lower().split()
		flags.sort()

		# Convert from GHz/MHz string to Hz
		scale = 6
		hz_advertised = kstat.split('\tclock_MHz ')[1].split('\n')[0].strip()
		hz_advertised = to_hz_string(hz_advertised)

		# Convert from GHz/MHz string to Hz
		hz_actual = kstat.split('\tcurrent_clock_Hz ')[1].split('\n')[0].strip()
		hz_actual = to_hz_string(hz_actual)

		# Get the CPU arch and bits
		arch, bits = parse_arch(DataSource.raw_arch_string)

		return {
		'vendor_id' : vendor_id,
		'hardware' : '',
		'brand' : processor_brand,

		'hz_advertised' : to_friendly_hz(hz_advertised, scale),
		'hz_actual' : to_friendly_hz(hz_actual, 0),
		'hz_advertised_raw' : to_raw_hz(hz_advertised, scale),
		'hz_actual_raw' : to_raw_hz(hz_actual, 0),

		'arch' : arch,
		'bits' : bits,
		'count' : DataSource.cpu_count,
		'raw_arch_string' : DataSource.raw_arch_string,

		'l2_cache_size' : cache_size,
		'l2_cache_line_size' : 0,
		'l2_cache_associativity' : 0,

		'stepping' : stepping,
		'model' : model,
		'family' : family,
		'processor_type' : 0,
		'extended_model' : 0,
		'extended_family' : 0,
		'flags' : flags
		}
	except:
		return None

def get_cpu_info():
	info = None

	# Try the Windows registry
	if not info:
		info = get_cpu_info_from_registry()

	# Try /proc/cpuinfo
	if not info:
		info = get_cpu_info_from_proc_cpuinfo()

	# Try sysctl
	if not info:
		info = get_cpu_info_from_sysctl()

	# Try kstat
	if not info:
		info = get_cpu_info_from_kstat()

	# Try dmesg
	if not info:
		info = get_cpu_info_from_dmesg()

	# Try sysinfo
	if not info:
		info = get_cpu_info_from_sysinfo()

	# Try querying the CPU cpuid register
	if not info:
		info = get_cpu_info_from_cpuid()

	return info