#pragma once

#include <nexus/error_code.hpp>
#include <nexus/detail/completion.hpp>
#include <nexus/quic/client.hpp>
#include <nexus/quic/server.hpp>

namespace nexus::quic {

class stream {
 protected:
  friend class client_connection;
  friend class server_connection;
  detail::stream_state state;
  explicit stream(detail::connection_state& cstate) : state(cstate) {}
 public:
  explicit stream(server_connection& c) : stream(c.state) {}
  explicit stream(client_connection& c) : stream(c.state) {}

  using executor_type = detail::stream_state::executor_type;
  executor_type get_executor() { return state.get_executor(); }

  template <typename CompletionToken> // void(error_code)
  auto async_connect(CompletionToken&& token) {
    using Signature = void(error_code);
    auto init = asio::async_completion<CompletionToken, Signature>{token};
    state.async_connect(detail::stream_connect_completion::create(
            get_executor(), std::move(init.completion_handler)));
    return init.result.get();
  }

  void connect(error_code& ec) {
    state.connect(ec);
  }
  void connect() {
    error_code ec;
    state.connect(ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  template <typename CompletionToken> // void(error_code)
  auto async_accept(CompletionToken&& token) {
    using Signature = void(error_code);
    auto init = asio::async_completion<CompletionToken, Signature>{token};
    state.async_accept(detail::stream_accept_completion::create(
            get_executor(), std::move(init.completion_handler)));
    return init.result.get();
  }

  void accept(error_code& ec) {
    state.accept(ec);
  }
  void accept() {
    error_code ec;
    state.accept(ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code)
  auto async_read_some(const MutableBufferSequence& buffers,
                       CompletionToken&& token) {
    using Signature = void(error_code, size_t);
    auto init = asio::async_completion<CompletionToken, Signature>{token};
    state.async_read(buffers, std::move(init.completion_handler));
    return init.result.get();
  }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, error_code& ec) {
    return state.read(buffers, ec);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.read(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  template <typename ConstBufferSequence,
            typename CompletionToken> // void(error_code)
  auto async_write_some(const ConstBufferSequence& buffers,
                       CompletionToken&& token) {
    using Signature = void(error_code, size_t);
    auto init = asio::async_completion<CompletionToken, Signature>{token};
    state.async_write(buffers, std::move(init.completion_handler));
    return init.result.get();
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers, error_code& ec) {
    return state.write(buffers, ec);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    error_code ec;
    const size_t bytes = state.write(buffers, ec);
    if (ec) {
      throw system_error(ec);
    }
    return bytes;
  }

  void shutdown(int how, error_code& ec) {
    state.shutdown(how, ec);
  }
  void shutdown(int how) {
    error_code ec;
    state.shutdown(how, ec);
    if (ec) {
      throw system_error(ec);
    }
  }

  void close(error_code& ec) {
    state.close(ec);
  }
  void close() {
    error_code ec;
    state.close(ec);
    if (ec) {
      throw system_error(ec);
    }
  }
};

} // namespace nexus::quic
