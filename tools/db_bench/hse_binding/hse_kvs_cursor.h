#ifndef STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_CURSOR_H_
#define STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_CURSOR_H_

#include "leveldb/slice.h"
#include "leveldb/status.h"

struct hse_kvs_cursor;

namespace leveldb {

class HseKvsCursor {
 public:
  HseKvsCursor(hse_kvs_cursor* handle);
  ~HseKvsCursor();

  HseKvsCursor(const HseKvsCursor&) = delete;
  HseKvsCursor& operator=(const HseKvsCursor&) = delete;

  void Read();
  void Seek(const Slice& key);
  bool Valid();

  Slice key();
  Slice value();

 private:
  hse_kvs_cursor* kvs_cursor_handle_;
  const void* current_key_;
  const void* current_value_;
  size_t current_key_size_;
  size_t current_value_size_;
  bool valid_;
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_HSE_BINDING_HSE_KVS_CURSOR_H_
