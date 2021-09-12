#pragma once

#include <condition_variable>
#include <optional>
#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>

struct iovec;

namespace nexus::quic {

namespace http3 {
class fields;
} // namespace http3

namespace detail {

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

struct accept_request : engine_request {
};

struct stream_connect_request : engine_request {
};
struct stream_accept_request : engine_request {
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

} // namespace detail
} // namespace nexus::quic
