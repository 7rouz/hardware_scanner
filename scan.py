from hardware_scanner.scanner import Scanner
from hardware_scanner.hard_arch import Hardware_Architecture
from hardware_scanner import cpu
from hardware_scanner.datasource import DataSource
from hardware_scanner.cpuid import CPUID

if __name__ == "__main__":
	sc = Scanner() 
	sc.cpu_scan()
	sc.memory_scan()
	sc.disk_scan()
	sc.network_scan()
	sc.users_scan()

	ha = Hardware_Architecture()
	ha.platform()
	ha.architecture()
	ha.hardware()

	print 
	print("this is the part where the info about this computer will be displaied :")
	print 

	# Make sure we are running on a supported system
	arch, bits = cpu.parse_arch(DataSource.raw_arch_string)
	if not arch in ['X86_32', 'X86_64', 'ARM_7', 'ARM_8']:
		sys.stderr.write("py-cpuinfo currently only works on X86 and ARM CPUs.\n")
		sys.exit(1)

	info = cpu.get_cpu_info()

	print('Vendor ID: {0}'.format(info.get('vendor_id', '')))
	print('Hardware Raw: {0}'.format(info.get('hardware', '')))
	print('Brand: {0}'.format(info.get('brand', '')))
	print('Hz Advertised: {0}'.format(info.get('hz_advertised', '')))
	print('Hz Actual: {0}'.format(info.get('hz_actual', '')))
	print('Hz Advertised Raw: {0}'.format(info.get('hz_advertised_raw', '')))
	print('Hz Actual Raw: {0}'.format(info.get('hz_actual_raw', '')))
	print('Arch: {0}'.format(info.get('arch', '')))
	print('Bits: {0}'.format(info.get('bits', '')))
	print('Count: {0}'.format(info.get('count', '')))

	print('Raw Arch String: {0}'.format(info.get('raw_arch_string', '')))

	print('L2 Cache Size: {0}'.format(info.get('l2_cache_size', '')))
	print('L2 Cache Line Size: {0}'.format(info.get('l2_cache_line_size', '')))
	print('L2 Cache Associativity: {0}'.format(info.get('l2_cache_associativity', '')))

	print('Stepping: {0}'.format(info.get('stepping', '')))
	print('Model: {0}'.format(info.get('model', '')))
	print('Family: {0}'.format(info.get('family', '')))
	print('Processor Type: {0}'.format(info.get('processor_type', '')))
	print('Extended Model: {0}'.format(info.get('extended_model', '')))
	print('Extended Family: {0}'.format(info.get('extended_family', '')))
	print('Flags: {0}'.format(', '.join(info.get('flags', ''))))