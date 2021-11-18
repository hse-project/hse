// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (C) 2021 Micron Technology, Inc.
//
// This code is derived from and modifies the LevelDB project.

#ifndef STORAGE_LEVELDB_HSE_BINDING_HSE_KVDB_H_
#define STORAGE_LEVELDB_HSE_BINDING_HSE_KVDB_H_

#include "leveldb/slice.h"
#include "leveldb/status.h"

#include "hse_binding/hse_kvs.h"

struct hse_kvdb;

namespace leveldb {

class HseKvdb {
 public:
  static Status Open(const std::string& kvdb_home, HseKvdb** kvdbptr);

  static void FiniLibrary();
  static void InitLibrary(const char* config);
  static std::string VersionString();

  HseKvdb(const HseKvdb&) = delete;
  HseKvdb& operator=(const HseKvdb&) = delete;

  Status Close();

  Status DropKvs(const std::string& kvs_name);
  Status MakeKvs(const std::string& kvs_name);
  Status OpenKvs(const std::string& kvs_name, HseKvs** kvsptr,
                 size_t get_buffer_size);

  Status Compact();

 private:
  std::string kvdb_home_;
  hse_kvdb* kvdb_handle_;

  HseKvdb(const std::string& kvdb_home);
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_HSE_BINDING_HSE_KVDB_H_
