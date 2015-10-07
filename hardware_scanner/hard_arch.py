import platform


class Hardware_Architecture:

	def architecture(self):
		print 
		print 'architecture :'
		print 'interpreter:', platform.architecture()
		print '/bin/ls    :', platform.architecture('/bin/ls')

	def hardware(self):
		print 
		print 'hardware :'
		print 'uname:', platform.uname()
		print
		print 'system   :', platform.system()
		print 'node     :', platform.node()
		print 'release  :', platform.release()
		print 'version  :', platform.version()
		print 'machine  :', platform.machine()
		print 'processor:', platform.processor()

	def platform(self):
		print 
		print 'platform :'
		print 'Version      :', platform.python_version()
		print 'Version tuple:', platform.python_version_tuple()
		print 'Compiler     :', platform.python_compiler()
		print 'Build        :', platform.python_build()