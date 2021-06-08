// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (C) 2021 Micron Technology, Inc.
//
// This code is derived from and modifies the LevelDB project.

#ifndef STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_H_
#define STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_H_

#include <string>

#include "leveldb/slice.h"
#include "leveldb/status.h"

#include "hse_binding/hse_kvs_cursor.h"

struct hse_kvs;

namespace leveldb {

class HseKvs {
 public:
  HseKvs(hse_kvs* handle, const std::string& kvs_name, size_t get_buffer_size);

  HseKvs(const HseKvs&) = delete;
  HseKvs& operator=(const HseKvs&) = delete;

  Status Close();

  Status Put(const Slice& key, const Slice& value);

  Status Delete(const Slice& key);

  Status Get(const Slice& key, std::string* value);

  Status GetInPlace(const Slice& key, void* dest, size_t dest_size,
                    size_t* value_size);

  HseKvsCursor* NewCursor(bool reverse = false);

  hse_kvs* kvs_handle_;
  std::string kvs_name_;

 private:
  void* get_buffer_;
  size_t get_buffer_size_;
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_H_
