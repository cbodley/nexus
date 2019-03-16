#pragma once

#include <http2/error.hpp>
#include <http2/protocol.hpp>

namespace http2 {

template <typename Stream>
class basic_connection {
 protected:
  Stream stream;
  protocol::setting_values settings;

 public:
  using next_layer_type = Stream;
  using lowest_layer_type = typename next_layer_type::lowest_layer_type;
  using executor_type = typename next_layer_type::executor_type;

  template <typename ...Args>
  basic_connection(const protocol::setting_values& settings, Args&& ...args)
    : stream(std::forward<Args>(args)...), settings(settings)
  {}

  next_layer_type& next_layer() { return stream; }
  const next_layer_type& next_layer() const { return stream; }
  lowest_layer_type& lowest_layer() { return stream.lowest_layer(); }
  const lowest_layer_type& lowest_layer() const { return stream.lowest_layer(); }
  executor_type get_executor() { return stream.get_executor(); }
};

} // namespace http2
