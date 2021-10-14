hsejni_sources = files(
    'hse_jni_util.c',
    'hsejni.c',
)

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
        component_root_includes,
    ],
    dependencies: [
        hse_internal_dep,
        jdk_dep,
        libhse_cli_dep,
    ],
    version: meson.project_version(),
    soversion: '0',
    install: true,
)

hsejni_dep = declare_dependency(
    link_with: hsejni,
    include_directories: [
        hsejni_includes,
    ],
)
