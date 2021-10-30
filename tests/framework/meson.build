subdir('include')
subdir('lib')

hse_test_framework = static_library(
    '@0@-test-framework'.format(meson.project_name()),
    hse_test_framework_sources,
    include_directories: hse_test_framework_includes,
    dependencies: hse_internal_dep,
    gnu_symbol_visibility: 'hidden'
)

hse_test_framework_dep = declare_dependency(
    link_with: hse_test_framework,
    include_directories: hse_test_framework_includes
)
