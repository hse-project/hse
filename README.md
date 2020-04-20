# HSE: Heterogeneous-Memory Storage Engine

**HSE** is an embeddable
key-value store designed for SSDs based on NAND flash or persistent memory.
HSE optimizes performance and endurance by orchestrating data
placement across DRAM and multiple classes of SSDs or other
solid-state storage.

HSE is ideal for powering NoSQL, Software-Defined Storage (SDS),
High-Performance Computing (HPC), Big Data,
Internet of Things (IoT), and Artificial Intelligence (AI) solutions.

## Key Features

* Standard and advanced key-value operators
* Full transactions with snapshot-isolation spanning multiple independent
key-value collections
* Cursors for iterating over snapshot views
* Data model for optimizing mixed use-case workloads in a single data store
* Flexible durability controls
* Configurable data orchestration schemes
* C API library that can be embedded in any application

## Benefits

* Scales to terabytes of data and hundreds of billions of keys per store
* Efficiently handles thousands of concurrent operations
* Dramatically improves throughput, latency, write-amplification,
and read-amplification versus common alternatives for many workloads
* Optionally combines multiple classes of solid-state storage to
optimize performance and endurance

# Getting Started

The [HSE Wiki](https://github.com/hse-project/hse/wiki)
contains all the information you need to get started with HSE.

# YCSB Performance Results

[YCSB](https://github.com/brianfrankcooper/YCSB)
(Yahoo!&reg; Cloud Serving Benchmark) is an industry-standard
benchmark for databases and storage engines supporting key-value
workloads.
The following table summarizes several YCSB workload mixes,
with application examples taken from the YCSB documentation.

| YCSB Workload | Operations | Application Example |
| :-- | :-- | :-- |
| A | 50% Read; 50% Update | Session store recording user-session activity |
| B | 95% Read; 5% Update | Photo tagging |
| C | 100% Read | User profile cache |
| D | 95% Read; 5% Insert | User status updates |


We integrated HSE with YCSB to make it easy to compare its performance
and scalability to that of other storage engines for YCSB workloads.
Below are throughput results from running YCSB with HSE.

For comparison, we include results from [RocksDB](https://rocksdb.org/),
a popular and widely-deployed key-value store.  For these YCSB workloads,
HSE delivered up to nearly 6x more throughput than RocksDB.

<img src="img/HSE-RocksDB-YCSB-Tput.png?raw=true">

System configuration details and additional performance results can be
found in the [YCSB section](https://github.com/hse-project/hse/wiki/YCSB)
of the HSE Wiki.

We also integrated HSE with [MongoDB&reg;](https://github.com/mongodb/mongo),
a popular NoSQL database, to validate its benefits within a real-world
storage application.  Below are throughput results from running
YCSB with MongoDB using HSE (MongoDB/HSE).

For comparison, we include results from MongoDB using the default WiredTiger
storage engine (MongoDB/WiredTiger).  For these YCSB workloads, MongoDB/HSE
delivered up to nearly 8x more throughput than MongoDB/WiredTiger.

<img src="img/HSE-MongoDB-YCSB-Tput.png?raw=true">

System configuration details and additional performance results can be found
in the [MongoDB section](https://github.com/hse-project/hse/wiki/MongoDB)
of the HSE Wiki.
