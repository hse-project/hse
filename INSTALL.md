# Installing

## HSE Dependencies

HSE has the following dependencies:

* [libcurl](https://github.com/curl/curl)
* [libyaml](https://github.com/yaml/libyaml)
* [userspace-rcu](https://liburcu.org/)
* [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/)
* [libbsd](https://libbsd.freedesktop.org/wiki/)
* [cJSON](https://github.com/DaveGamble/cJSON)
* [lz4](https://github.com/lz4/lz4)
* [xxHash](https://github.com/Cyan4973/xxHash)

Note that by default cJSON, lz4, and xxHash are built as a part of HSE using
Meson subprojects for performance and embedding reasons. To use system pacakges
for cJSON, lz4, and xxHash, setup your build with the following:

```shell
meson setup build -Duse-system-cjson=true -Duse-system-lz4=true \
    -Duse-system-xxhash=true
```

Depending on the build configuration, HSE has the following additional
dependencies for various internal tools:

* [mongo-c-driver](https://github.com/mongodb/mongo-c-driver)
* [ncurses](https://invisible-island.net/ncurses/announce.html)
* [HdrHistogram_c](https://github.com/HdrHistogram/HdrHistogram_c)
* [doxygen](https://www.doxygen.nl/index.html)
* [graphviz](https://graphviz.org/)

In addition to the above, we strongly recommend installing the build component
or meta package for your system.

```shell
# RHEL-based
sudo dnf install "@Development Tools"
# Ubuntu-based
sudo apt install build-essential
```

## Dependencies From System

To obtain these from you system's package manager:

### RHEL 8

```shell
sudo dnf install libcurl-devel libyaml-devel userspace-rcu-devel \
    libmicrohttpd-devel libbsd-devel
# Optionally, depending on the your build settings
sudo dnf install cjson-devel lz4-devel xxhash-devel mongo-c-driver-devel \
    ncurses-devel HdrHistogram_c-devel doxygen graphviz
```

### Ubuntu 18.04

The versions of libbsd and mongo-c-driver in the repository are too low. In
this case, the HSE build will fall back to using libbsd from a Meson
subproject. cJSON, xxHash, and HdrHistogram_c aren't packaged for this
distribution.

```shell
sudo apt install libcurl4-openssl-dev libyaml-dev liburcu-dev \
    libmicrohttpd-dev
# Optionally, depending on the your build settings.
sudo apt install liblz4-dev libncurses-dev doxygen graphviz
```

## Dependencies from Meson Subprojects

Meson has support for subprojects which depending on your build configuration
and environment will build software that the top-level project (HSE) depends on.

In the event your build configuration specifies the need for subprojects or you
don't have the right packages or versions in the host environment, the
subprojects will be transparently built as a part of HSE. Take note that using
subprojects can increase build times. **HSE has subproject definitions for all
of its direct dependencies.** When building HSE's subprojects, make sure to
have the dependencies for the subprojects satisfied. These include common tools
like `autoconf` and `libtool`.
