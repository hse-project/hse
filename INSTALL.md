# Installing

## HSE Dependencies

HSE has the following dependencies[^1]:

* [cJSON](https://github.com/DaveGamble/cJSON) `>= 1.7.14`
* [libbsd](https://libbsd.freedesktop.org/wiki/) `>= 0.9.0`
* [libcurl](https://github.com/curl/curl) `>=7.58.0`
* [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/) `>= 0.9.59`
* [libyaml](https://github.com/yaml/libyaml) `>= 1.7`
* [lz4](https://github.com/lz4/lz4) `>= 1.9.2`
* [userspace-rcu](https://liburcu.org/) `>= 0.10.1`
* [xxHash](https://github.com/Cyan4973/xxHash) `>= 0.8`
* [libpmem](https://github.com/pmem/pmdk)[^2] `>= 1.4`

Note that by default cJSON, lz4, and xxHash are built as a part of HSE using
Meson subprojects for performance and embedding reasons. To use system pacakges
for cJSON, lz4, and xxHash, setup your build with the following:

```shell
meson setup build -Dforce_fallback_for=
```

Depending on the build configuration, HSE has the following additional
dependencies for various internal tools and documentation:

* [mongo-c-driver](https://github.com/mongodb/mongo-c-driver) `>= 1.17.3`
* [ncurses](https://invisible-island.net/ncurses/announce.html) `>= 6.1.20180127`
* [HdrHistogram_c](https://github.com/HdrHistogram/HdrHistogram_c) `>= 0.11.2`
* [doxygen](https://www.doxygen.nl/index.html)

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
# Optionally, depending on the your build configuration
sudo dnf install cjson-devel lz4-devel xxhash-devel mongo-c-driver-devel \
    ncurses-devel HdrHistogram_c-devel doxygen
# For optimal persistent memory (pmem) media class support on x86 architecture
sudo dnf install libpmem-devel
```

### Ubuntu 18.04

The versions of libbsd and mongo-c-driver in the repository are too low. In
this case, the HSE build will fall back to using libbsd from a Meson
subproject. cJSON, xxHash, and HdrHistogram_c aren't packaged for this
distribution.

```shell
sudo apt install libcurl4-openssl-dev libyaml-dev liburcu-dev \
    libmicrohttpd-dev
# Optionally, depending on the your build configuration.
sudo apt install liblz4-dev libncurses-dev doxygen
# For optimal persistent memory (pmem) media class support on x86 architecture
sudo dnf install libpmem-dev
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

[^1]: _The minimum versions of some dependencies may be lower than what is listed.
The listed versions are what we know works and test against._

[^2]: _Only required if you intend to make use of persistent memory on
`x86`._
