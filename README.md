# HSE: Heterogeneous-Memory Storage Engine

**HSE** is a fast embeddable key-value store designed for SSDs and
persistent memory.
HSE optimizes performance and endurance by orchestrating data
placement across DRAM and multiple classes of solid-state storage.

HSE is ideal for powering Databases, Software-Defined Storage (SDS),
High-Performance Computing (HPC), Internet of Things (IoT),
and Machine Learning (ML).

**Key Features:**

* Rich set of key-value operators
* Full transactions with snapshot-isolation spanning multiple independent
key-value collections
* Cursors for iterating over snapshot views
* Data model for optimizing mixed use-case workloads in a single data store
* Key and value compression
* Flexible durability controls
* Configurable data orchestration schemes
* Native C library that can be embedded in any application

**Benefits:**

* Scales to terabytes of data and hundreds of billions of keys per store
* Efficiently handles thousands of concurrent operations
* Dramatically improves throughput, latency, write-amplification,
and read-amplification versus common alternatives for many workloads
* Optionally combines multiple classes of solid-state storage to
optimize performance and endurance

## Getting Started

The HSE [project documentation](https://hse-project.github.io/)
contains all the information you need to get started with HSE.

## Building and Installing

Follow the steps below to build and install HSE.

### Dependencies

You may need to install additional packages to build or run HSE for your
particular Linux distribution and environment.
See [`INSTALL.md`](https://github.com/hse-project/hse/blob/master/INSTALL.md)
for examples of the packages required for several common Linux distributions.

### Building HSE

<!--If you change the name of this header, please update all links to it as well-->

Clone the [`hse`](https://github.com/hse-project/hse) repo and checkout
the latest release tag.  This tag must be for HSE version 2.0 or higher.

For example

```shell
git clone https://github.com/hse-project/hse.git
cd hse
git checkout <release tag>
```

Build and install using Meson and Ninja.

The minimum version of Meson required to build HSE can be found in the root
[meson.build](./meson.build). In there, you will find a `meson_version`
keyword argument to the `project()` function at the beginnging of the file.

If your system doesn't supply a Meson version new enough to build HSE, refer to
the Meson
[installation instructions](https://mesonbuild.com/Getting-meson.html).

```shell
meson setup build
meson compile -C build
meson install -C build
```

The default install directory is `/opt/hse`. This can be overridden by
configuring the build with either `-Dprefix=$prefix` or `--prefix=$prefix`.

## Additional References

Information on running test suites and contributing to HSE is located in the
[`CONTRIBUTING.md`](./CONTRIBUTING.md) file.

We integrated HSE with several common applications to demonstrate its
capabilities.

* YCSB: See [`README.md`](https://github.com/hse-project/hse-ycsb/blob/v0.17.0-hse/hse/README.md) in the [`hse-ycsb`](https://github.com/hse-project/hse-ycsb) repo.
* MongoDB: See [`README.md`](https://github.com/hse-project/hse-mongo/blob/v3.4.17-hse/src/mongo/db/storage/hse/README.md) in the [`hse-mongo`](https://github.com/hse-project/hse-mongo) repo.
