// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (C) 2021 Micron Technology, Inc.
//
// This code is derived from and modifies the LevelDB project.

#include <chrono>
#include <thread>

#include "leveldb/slice.h"
#include "leveldb/status.h"

#include <hse/hse.h>
#include <hse/version.h>

#include "hse_binding/hse_kvdb.h"
#include "hse_binding/hse_kvs.h"
#include "hse_binding/hse_kvs_cursor.h"

namespace leveldb {

static const int MSG_SIZE = 100;

HseKvdb::HseKvdb(const std::string& kvdb_home) : kvdb_home_(kvdb_home) {}

void HseKvdb::InitLibrary(const std::string& config) { hse_init(config.c_str(), 0, nullptr); }

void HseKvdb::FiniLibrary() { hse_fini(); }

std::string HseKvdb::VersionString() {
  return std::string(HSE_VERSION_STRING);
}

Status HseKvdb::Open(const std::string& kvdb_home, HseKvdb** kvdbptr) {
  HseKvdb* kvdb = new HseKvdb(kvdb_home);
  hse_err_t err;

  err = hse_kvdb_open(kvdb_home.c_str(), 0, NULL, &kvdb->kvdb_handle_);
  if (err) {
    char msg[MSG_SIZE];
    delete kvdb;
    hse_strerror(err, msg, sizeof(msg));
    return Status::IOError(msg);
  }

  *kvdbptr = kvdb;

  return Status::OK();
}

Status HseKvdb::Close() {
  hse_err_t err;

  if (kvdb_handle_ != nullptr) {
    err = hse_kvdb_close(kvdb_handle_);
    kvdb_handle_ = nullptr;

    if (err) {
      char msg[MSG_SIZE];
      hse_strerror(err, msg, sizeof(msg));
      return Status::IOError(msg);
    }
  }

  return Status::OK();
}

Status HseKvdb::OpenKvs(const std::string& kvs_name, HseKvs** kvsptr,
                        size_t get_buffer_size) {
  HseKvs* kvs;
  hse_kvs* kvs_handle;
  hse_err_t err;

  std::fprintf(stderr, "open kvs \"%s\" in kvdb \"%s\"\n", kvs_name.c_str(), kvdb_home_.c_str());

  err = hse_kvdb_kvs_open(kvdb_handle_, kvs_name.c_str(), 0, NULL, &kvs_handle);
  if (err) {
    char msg[MSG_SIZE];
    hse_strerror(err, msg, sizeof(msg));
    return Status::IOError(msg);
  }

  kvs = new HseKvs(kvs_handle, kvs_name, get_buffer_size);
  *kvsptr = kvs;

  std::fprintf(stderr, "open kvs \"%s\" in kvdb \"%s\" ok\n", kvs_name.c_str(), kvdb_home_.c_str());

  return Status::OK();
}

Status HseKvdb::DropKvs(const std::string& kvs_name) {
  hse_err_t err;

  std::fprintf(stderr, "drop kvs \"%s\" in kvdb \"%s\"\n", kvs_name.c_str(), kvdb_home_.c_str());

  err = hse_kvdb_kvs_drop(kvdb_handle_, kvs_name.c_str());
  if (err) {
    char msg[MSG_SIZE];
    hse_strerror(err, msg, sizeof(msg));
    return Status::IOError(msg);
  }

  std::fprintf(stderr, "drop kvs \"%s\" in kvdb \"%s\" ok\n", kvs_name.c_str(), kvdb_home_.c_str());

  return Status::OK();
}

Status HseKvdb::MakeKvs(const std::string& kvs_name) {
  hse_err_t err;

  std::fprintf(stderr, "create kvs \"%s\" in kvdb \"%s\"\n", kvs_name.c_str(), kvdb_home_.c_str());

  err = hse_kvdb_kvs_create(kvdb_handle_, kvs_name.c_str(), 0, NULL);
  if (err) {
    char msg[MSG_SIZE];
    hse_strerror(err, msg, sizeof(msg));
    return Status::IOError(msg);
  }

  std::fprintf(stderr, "create kvs \"%s\" in kvdb \"%s\" ok\n", kvs_name.c_str(), kvdb_home_.c_str());

  return Status::OK();
}

Status HseKvdb::Compact() {
  hse_err_t err;
  hse_kvdb_compact_status status;
  char msg[MSG_SIZE];

  memset(&status, 0, sizeof(status));

  err = hse_kvdb_compact(kvdb_handle_, HSE_KVDB_COMPACT_SAMP_LWM);

  if (err) {
    hse_strerror(err, msg, sizeof(msg));
    return Status::IOError(msg);
  }

  do {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    err = hse_kvdb_compact_status_get(kvdb_handle_, &status);

    if (err) {
      hse_strerror(err, msg, sizeof(msg));
      return Status::IOError(msg);
    }
  } while (status.kvcs_active != 0);

  return Status::OK();
}

}  // namespace leveldb
