#pragma once

#include <condition_variable>
#include <optional>
#include <boost/intrusive/list.hpp>
#include <nexus/error_code.hpp>
#include <nexus/quic/http3/fields.hpp>

struct iovec;
struct lsxpack_header;
struct sockaddr;

namespace nexus::quic::detail {

struct engine_request : boost::intrusive::list_base_hook<> {
  std::condition_variable* cond = nullptr;
  std::optional<error_code> ec;

  void notify(error_code ec) {
    this->ec = ec;
    if (cond) {
      cond->notify_one();
    }
  }
};

struct connect_request : engine_request {
  const asio::ip::udp::endpoint* endpoint = nullptr;
  const char* hostname = nullptr;
};
struct accept_request : engine_request {
};
struct close_request : engine_request {
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
struct stream_flush_request : engine_request {
};
struct stream_shutdown_request : engine_request {
  int how = 0;
};
struct stream_close_request : engine_request {
};

} // namespace nexus::quic::detail
