// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (C) 2021 Micron Technology, Inc.
//
// This code is derived from and modifies the LevelDB project.

#include "hse_binding/hse_kvs_cursor.h"

#include <hse/hse.h>

#include "leveldb/status.h"

namespace leveldb {

static const int MSG_SIZE = 100;

HseKvsCursor::HseKvsCursor(hse_kvs_cursor* handle)
    : kvs_cursor_handle_(handle),
      current_key_(nullptr),
      current_value_(nullptr),
      current_key_size_(0),
      current_value_size_(0),
      valid_(false) {}

HseKvsCursor::~HseKvsCursor() {
  if (kvs_cursor_handle_ != nullptr) {
    hse_kvs_cursor_destroy(kvs_cursor_handle_);
  }
}

Slice HseKvsCursor::key() {
  return Slice((const char*)current_key_, current_key_size_);
}

Slice HseKvsCursor::value() {
  return Slice((const char*)current_value_, current_value_size_);
}

void HseKvsCursor::Read() {
  hse_err_t err;
  bool eof;

  err = hse_kvs_cursor_read(kvs_cursor_handle_, 0, &current_key_,
                            &current_key_size_, &current_value_,
                            &current_value_size_, &eof);

  if (err) {
    char msg[MSG_SIZE];
    valid_ = false;
    current_key_ = nullptr;
    current_value_ = nullptr;
    hse_err_to_string(err, msg, sizeof(msg), NULL);
    std::fprintf(stderr, "cursor read error: %s\n", msg);
  } else if (eof) {
    valid_ = false;
  } else {
    valid_ = true;
  }
}

void HseKvsCursor::Seek(const Slice& target) {
  hse_err_t err;

  err = hse_kvs_cursor_seek(kvs_cursor_handle_, 0, target.data(),
                            target.size(), nullptr, nullptr);
  if (err) {
    char msg[MSG_SIZE];
    hse_err_to_string(err, msg, sizeof(msg), NULL);
    std::fprintf(stderr, "cursor seek error: %s\n", msg);
    valid_ = false;
  } else {
    valid_ = true;
  }
}

bool HseKvsCursor::Valid() { return valid_; }

}  // namespace leveldb
