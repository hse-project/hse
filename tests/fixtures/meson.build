subdir('include')
subdir('lib')

hse_fixtures = static_library(
    '@0@-fixtures'.format(meson.project_name()),
    hse_fixtures_sources,
    include_directories: hse_fixtures_includes,
    dependencies: hse_internal_dep,
    gnu_symbol_visibility: 'hidden'
)

hse_fixtures_dep = declare_dependency(
    link_with: hse_fixtures,
    include_directories: hse_fixtures_includes,
    dependencies: hse_internal_dep
)
