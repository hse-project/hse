subdir('include')
subdir('lib')

hse_test_fixtures = static_library(
    '@0@-test-fixtures'.format(meson.project_name()),
    test_fixtures_sources,
    include_directories: test_fixtures_includes,
    dependencies: hse_internal_dep,
    gnu_symbol_visibility: 'hidden'
)

hse_test_fixtures_dep = declare_dependency(
    link_with: hse_test_fixtures,
    include_directories: [
        # Exposes merr_t in a public header
        component_root_includes,
        test_fixtures_includes,
    ],
    dependencies: hse_internal_dep
)
