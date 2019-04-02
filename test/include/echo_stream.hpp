#pragma once

#include <boost/asio/streambuf.hpp>

#include <detail/echo_stream.hpp>

namespace nexus::test {

// a stream that buffers writes and echos them back on reads
template <typename Executor, typename DynamicBuffer = boost::asio::streambuf>
class echo_stream {
  Executor ex;
  detail::echo_impl<DynamicBuffer> impl;

 public:
  template <typename ...Args>
  echo_stream(const Executor& ex, Args&& ...args)
    : ex(ex), impl(std::in_place, std::forward<Args>(args)...)
  {}

  using executor_type = Executor;
  executor_type get_executor() const noexcept { return ex; }

  using next_layer_type = echo_stream;
  next_layer_type& next_layer() { return *this; }

  using lowest_layer_type = echo_stream;
  lowest_layer_type& lowest_layer() { return *this; }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    boost::system::error_code ec;
    read_some(buffers, ec);
    if (ec)
      throw boost::system::system_error(ec);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers,
                   boost::system::error_code& ec) {
    return impl.read_some(buffers, ec);
  }

  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    boost::system::error_code ec;
    size_t bytes = write_some(buffers, ec);
    if (ec)
      throw boost::system::system_error(ec);
    return bytes;
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers,
                   boost::system::error_code& ec) {
    return impl.write_some(buffers, ec);
  }

  template <typename MutableBufferSequence, typename ReadHandler>
  auto async_read_some(const MutableBufferSequence& buffers,
                       ReadHandler&& token) {
    using Signature = void(boost::system::error_code, size_t);
    boost::asio::async_completion<ReadHandler, Signature> init(token);
    auto& handler = init.completion_handler;
    auto ex1 = get_executor();
    auto ex2 = boost::asio::get_associated_executor(handler, ex1);
    auto alloc = boost::asio::get_associated_allocator(handler);
    ex2.post(detail::echo_read_op{impl, buffers, ex1, std::move(handler)}, alloc);
    return init.result.get();
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  auto async_write_some(const ConstBufferSequence& buffers,
                        WriteHandler&& token) {
    using Signature = void(boost::system::error_code, size_t);
    boost::asio::async_completion<WriteHandler, Signature> init(token);
    auto& handler = init.completion_handler;
    auto ex1 = get_executor();
    auto ex2 = boost::asio::get_associated_executor(handler, ex1);
    auto alloc = boost::asio::get_associated_allocator(handler);
    ex2.post(detail::echo_write_op{impl, buffers, ex1, std::move(handler)}, alloc);
    return init.result.get();
  }

  void cancel() {
    impl.cancel();
  }
  void close() {
    impl.close();
  }
};

} // namespace nexus::test
