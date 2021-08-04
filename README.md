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

> TODO: Document how to build an install HSE as a user.  I.e., someone
> who is going to write (or run) an HSE client application.
> Documentation on building and testing for HSE development belongs
> in `CONTRIBUTING.md.`


## Additional References

Information on running test suites and contributing to HSE is located in the
[`CONTRIBUTING.md`](https://github.com/hse-project/hse/blob/master/CONTRIBUTING.md) file.

