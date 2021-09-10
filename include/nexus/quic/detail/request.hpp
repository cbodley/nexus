#pragma once

#include <condition_variable>
#include <optional>
#include <nexus/error_code.hpp>
#include <nexus/quic/http3/fields.hpp>

struct iovec;
struct lsxpack_header;

namespace nexus::quic::detail {

struct engine_request {
  std::condition_variable* cond = nullptr;
  std::optional<error_code> ec;

  void notify(error_code ec) {
    this->ec = ec;
    if (cond) {
      cond->notify_one();
    }
  }
};

struct conn_open_request : engine_request {
  const sockaddr* remote_endpoint = nullptr;
  const char* remote_hostname = nullptr;
};
struct conn_close_request : engine_request {
};

struct stream_open_request : engine_request {
};
struct stream_data_request : engine_request {
  iovec* iovs = nullptr;
  uint16_t num_iovs = 0;
  size_t bytes = 0;
};
struct stream_header_read_request : engine_request {
  http3::fields* fields = nullptr;
};
struct stream_header_write_request : engine_request {
  const http3::fields* fields = nullptr;
};
struct stream_flush_request : engine_request {
};
struct stream_shutdown_request : engine_request {
  int how = 0;
};
struct stream_close_request : engine_request {
};

} // namespace nexus::quic::detail
