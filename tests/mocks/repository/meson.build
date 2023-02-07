# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

subdir('lib')

hse_mock_repository = static_library(
    '@0@-mock-repository'.format(meson.project_name()),
    hse_mock_repository_sources,
    include_directories: [
        hse_include_directories,
        hse_mock_include_directories,
    ],
    dependencies: [
        hse_mock_dep,
        hse_dependencies,
    ],
)

hse_mock_repository_dep = declare_dependency(
    link_with: hse_mock_repository,
    include_directories: [
    ],
)
