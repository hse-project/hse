<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
-->

# HSE Instance-level relationships

For reference, see [wikipedia](https://en.wikipedia.org/wiki/Class_diagram#Instance-level_relationships).

Terminology:

- **aggregation**: Models a part/whole relationship where the part can
  exist without the whole.  The part and the whole have a
  weak lifecycle dependency.
- **composition**: Models a part/whole relationship where part can not
  exist without whole.  The part and the whole have a strong lifecycle
  dependency.
- **X has a Y**: X and Y have an aggregation relationship
- **X contains a Y** : X and Y have composition relationship
- **X is a Y**: X and Y are the same object

## HSE Object Types

    Common Name      Underlying struct types
    -----------      ------------------------------
    kvdb             hse_kvdb
    ikvdb            ikvdb, ikvdb_impl
    c0sk             c0sk,  c0sk_impl
    kvms             c0_kvmultiset, c0_kvmultiset_impl
    c0_kvset         c0_kvset, c0_kvset_impl
    c0               c0, c0_impl
    cn               cn
    kvs              hse_kvs (alias for kvdb_kvs)
    kvdb_kvs         kvdb_kvs
    ikvs             ikvs
    c0snr_set        c0snr_set, c0snr_set_impl

## HSE Instance Relationships

    - A hse_kvdb is an ikvdb

    - Each ikvdb:
      - contains one c0sk
      - contains one c0snr_set
      - contains zero or more kvdb_kvs (up to 256)

    - Each c0sk:
      - contains one or more kvms (limit?)
      - contains a array of refs to cn  // c0sk_cnv[]

    - Each kvms:
      - contains one or more c0_kvset (up to 32)

    - Each c0_kvset:
      - contains a cheap allocator
      - contains a bonsai tree

    - An hse_kvs is an kvdb_kvs

    - Each kvdb_kvs:
      - contains an ikvs

    - Each ikvs:
      - contains a cursor cache
      - contains a cn                // ikvs->ikv_cn
      - contains a c0                // ikvs->ikv_c0

    - Each c0:
      - references a c0sk        // the one that is owned by ikvdb
      - is associated with a cn  // by way of "skidx" which is an index
                                 // into c0sk's array or refs to cn(c0sk_cnv)

## HSE Instance Relationships Diagram

                 +=======================+          +===========+
                 |     hse_kvdb          |<*>~~~~~~~| c0snr_set |
                 |       ikvdb           |          +===========+
                 |                       |<*>~~+
                 +=======================+     |    +===========+
                       <*>    <*>              +~~~~|    IC     |
                        |      |                    +===========+
                 +~~~~~~+      +~~~~~~~+
                 |                     |
                 |0..256               |
              +==========+        +==================+
              | kvdb_kvs |        |       c0sk       |
              +==========+        +==================+
                   <*>               :          <*>
                    |                :           |
                    |                :           |1..N
         +=======================+   :       +==============+
         |       ikvs            |   :       |   kvms       |
         +=======================+   :       +==============+
           <*>   <*>         <*>     :                <*>
            |     |           |      :                 |
            |     |           |      :0..256           |0..32
            |  +=====+      +=============+      +==============+
            |  |  c0 |......|     cn      |      |   c0_kvset   |
            |  +=====+      +=============+      +==============+
            |                                       <*>     <*>
         +========+                                  |       |
         | cursor |                                  |       |
         | cache  |                            +=======+   +========+
         +========+                            | cheap |   | bonsai |
                                               +=======+   | tree   |
                                                           +========+

    Key:
    - Composition: A solid line (~ or |) terminated with "<*>" on one end
    - Aggregation: A dotted line (. or :)
