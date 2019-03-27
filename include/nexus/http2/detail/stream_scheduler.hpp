#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>

#include <boost/beast/core/buffers_suffix.hpp>
#include <boost/beast/http/type_traits.hpp>

#include <nexus/http2/error.hpp>
#include <nexus/http2/detail/stream.hpp>

namespace nexus::http2::detail {

namespace bi = boost::intrusive;

template <typename T>
constexpr bool is_fields_v = boost::beast::http::is_fields<T>::value;
template <typename T>
constexpr bool is_body_reader_v = boost::beast::http::is_body_reader<T>::value;
template <typename T>
constexpr bool is_body_writer_v = boost::beast::http::is_body_writer<T>::value;

template <typename Stream>
class stream_scheduler {
 public:
  using next_layer_type = Stream;
  using lowest_layer_type = typename next_layer_type::lowest_layer_type;
  using executor_type = typename next_layer_type::executor_type;
 protected:
  next_layer_type stream;
  stream_set streams;

  struct waiter : stream_waiter {
    protocol::stream_identifier stream_id;
    std::mutex mutex;
    std::condition_variable cond;
  };

  struct writer : waiter, bi::list_base_hook<> {
    size_t size; // number of output bytes available
  };
  // writers with flow control window available: min(size, frame_size)
  bi::list<writer> writers_ready;

  struct reader : waiter {
    std::optional<boost::system::error_code> result;
    void complete(boost::system::error_code ec) override {
      std::scoped_lock lock{this->mutex};
      result = ec;
      this->cond.notify_one();
    }
  };
 public:
  template <typename ...Args>
  stream_scheduler(std::in_place_t, Args&& ...args)
    : stream(std::forward<Args>(args)...)
  {}
  ~stream_scheduler() {
    streams.clear_and_dispose(std::default_delete<stream_impl>{});
  }

  next_layer_type& next_layer() { return stream; }
  const next_layer_type& next_layer() const { return stream; }
  lowest_layer_type& lowest_layer() { return stream.lowest_layer(); }
  const lowest_layer_type& lowest_layer() const { return stream.lowest_layer(); }
  executor_type get_executor() { return stream.get_executor(); }

  template <typename Fields>
  auto read_header(protocol::stream_identifier& stream_id,
                   Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<is_fields_v<Fields>, size_t>;

  template <typename BodyReader>
  size_t read_some_body(protocol::stream_identifier stream_id,
                        BodyReader& body,
                        boost::system::error_code& ec);

  template <typename Fields>
  auto write_header(protocol::stream_identifier& stream_id,
                    const Fields& fields, boost::system::error_code& ec)
    -> std::enable_if_t<is_fields_v<Fields>>;

  template <typename BodyWriter>
  size_t write_some_body(protocol::stream_identifier stream_id,
                         const BodyWriter& body,
                         boost::system::error_code& ec);
};

template <typename Stream>
template <typename Fields>
auto stream_scheduler<Stream>::read_header(
    protocol::stream_identifier& stream_id,
    [[maybe_unused]] Fields& fields,
    boost::system::error_code& ec)
  -> std::enable_if_t<is_fields_v<Fields>, size_t>
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return 0;
  }
  return 0;
}

template <typename Stream>
template <typename BodyReader>
size_t stream_scheduler<Stream>::read_some_body(
    protocol::stream_identifier stream_id,
    BodyReader& reader,
    boost::system::error_code& ec)
{
  if (stream_id == 0) {
    ec = make_error_code(protocol::error::protocol_error);
    return 0;
  }
  auto stream = this->streams.find(stream_id, stream_id_less{});
  if (stream == this->streams.end()) {
    ec = make_error_code(protocol::error::protocol_error);
    return 0;
  }
  {
    typename stream_scheduler<Stream>::reader r;
    std::unique_lock lock{r.mutex};
    stream->reader = &r;
    r.cond.wait(lock, [&r] { return r.result; });
    ec = *r.result;
    stream->reader = nullptr;
  }
  size_t count = 0;
  for (auto i = stream->buffers.begin(); i != stream->buffers.end(); ) {
    auto& buffer = *i;
    const size_t bytes = reader.put(buffer.data(), ec);
    count += bytes;
  }
  // TODO: return buffers to the pool
  // TODO: adjust flow control window
  return count;
}

} // namespace nexus::http2::detail
