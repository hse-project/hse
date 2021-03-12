# packagefiles

This directory is home to files that get copied into the unpacked subprojects.
Most of the subdirectories contain a single `meson.build` file. In the case of
`HdrHistogram_c` however, the project didn't conform to the `GNUInstallDirs` in
CMake and hardcoded its `libdir` install path as `lib`. Meson's CMake module
speaks `GNUInstallDirs`, so we help it along.
