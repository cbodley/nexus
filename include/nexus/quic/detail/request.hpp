#pragma once

#include <condition_variable>
#include <optional>
#include <sys/uio.h>
#include <nexus/error_code.hpp>
#include <nexus/udp.hpp>
#include <nexus/detail/completion.hpp>

namespace nexus::quic {

namespace http3 {
class fields;
} // namespace http3

namespace detail {

template <typename Signature, typename T = void>
using completion = nexus::detail::completion<Signature, T>;
template <typename T>
using as_base = nexus::detail::as_base<T>;

using basic_completion = completion<void(error_code)>;

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
using accept_completion = completion<void(error_code), accept_request>;

struct stream_connect_request : engine_request {
};
using stream_connect_completion = completion<void(error_code),
                                             stream_connect_request>;

struct stream_accept_request : engine_request {
};
using stream_accept_completion = completion<void(error_code),
                                            stream_accept_request>;

struct stream_data_request : engine_request {
  static constexpr uint16_t max_iovs = 128;
  iovec iovs[max_iovs];
  uint16_t num_iovs = 0;
  size_t bytes_transferred = 0;
};
using stream_data_completion = completion<void(error_code, size_t),
                                          stream_data_request>;

struct stream_header_read_request : engine_request {
  http3::fields* fields = nullptr;
};
using stream_header_read_completion = completion<void(error_code),
                                                 stream_header_read_request>;

struct stream_header_write_request : engine_request {
  const http3::fields* fields = nullptr;
};
using stream_header_write_completion = completion<void(error_code),
                                                  stream_header_write_request>;

} // namespace detail
} // namespace nexus::quic
