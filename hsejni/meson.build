add_languages('java', native: false)

jdk_dep = dependency('jdk', version : '>=1.8.0')

subdir('include')
subdir('java/hsejni/src')
subdir('src')
if get_option('tests')
	subdir('tests')
endif
