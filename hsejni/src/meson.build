hsejni_sources = files(
    'hse_jni_util.c',
    'hsejni.c',
)

java_home = run_command(
    'sh',
    '-c',
    'dirname $(dirname $(readlink -f $(which javac)))',
    check: true,
).stdout().strip()

hsejni_c_args = [
    '-DCOMPNAME="hsejni"',
]

hsejni = library(
    'hsejni',
    hsejni_sources,
    c_args: hsejni_c_args,
    include_directories: [
        public_includes,
        util_includes,
        hsejni_includes,
        include_directories(
            '@0@'.format(java_home) / 'include',
            '@0@'.format(java_home) / 'include' / 'linux'
        ),
    ],
    dependencies: [
        hse_dep,
        thread_dep,
    ],
    version: meson.project_version(),
    install: true,
)
