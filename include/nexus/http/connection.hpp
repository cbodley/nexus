#pragma once

#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <nexus/http/detail/connection_impl.hpp>

namespace nexus::http {

// a move-only handle to an open connection that meets the requirements
// of the AsyncStream and SyncStream concepts from boost::beast
class connection {
  friend class connection_pool;
  boost::intrusive_ptr<detail::connection_impl> impl;
 public:
  connection(boost::intrusive_ptr<detail::connection_impl>&& impl)
    : impl(std::move(impl)) {}

  connection(connection&&) = default;
  connection& operator=(connection&&) = default;
  connection(const connection&) = delete;
  connection& operator=(const connection&) = delete;

  using executor_type = detail::connection_impl::executor_type;
  executor_type get_executor() { return impl->get_executor(); }

  size_t available(boost::system::error_code& ec)
  {
    return impl->available(ec);
  }

  void shutdown(boost::system::error_code& ec)
  {
    impl->shutdown(ec);
  }

  void close(boost::system::error_code& ec)
  {
    impl->close(ec);
  }

  void cancel()
  {
    impl->cancel();
  }

  // SyncReadStream
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers)
  {
    return impl->read_some(buffers);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers,
                   boost::system::error_code& ec)
  {
    return impl->read_some(buffers, ec);
  }

  // SyncWriteStream
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers)
  {
    return impl->write_some(buffers);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
  {
    return impl->write_some(buffers, ec);
  }

  // AsyncReadStream
  template <typename MutableBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  auto async_read_some(const MutableBufferSequence& buffers,
                       CompletionToken&& token)
  {
    return impl->async_read_some(buffers, std::forward<CompletionToken>(token));
  }

  // AsyncWriteStream
  template <typename ConstBufferSequence,
            typename CompletionToken> // void(error_code, size_t)
  auto async_write_some(const ConstBufferSequence& buffers,
                       CompletionToken&& token)
  {
    return impl->async_write_some(buffers, std::forward<CompletionToken>(token));
  }
};

} // namespace nexus::http
