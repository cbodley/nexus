#pragma once

#include <cstddef>

namespace nexus::test {

// combines a separate ReadStream and WriteStream into a ReadWriteStream
template <typename ReadStream, typename WriteStream>
class joined_stream {
  ReadStream& in;
  WriteStream& out;
 public:
  joined_stream(ReadStream& in, WriteStream& out) : in(in), out(out) {}

  using executor_type = typename ReadStream::executor_type;
  executor_type get_executor() const noexcept { return in.get_executor(); }

  using next_layer_type = typename ReadStream::next_layer_type;
  next_layer_type& next_layer() { return in; }

  using lowest_layer_type = typename ReadStream::lowest_layer_type;
  lowest_layer_type& lowest_layer() { return in.lowest_layer(); }

  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    return in.read_some(buffers);
  }
  template <typename MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers,
                   boost::system::error_code& ec) {
    return in.read_some(buffers, ec);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers) {
    return out.write_some(buffers);
  }
  template <typename ConstBufferSequence>
  size_t write_some(const ConstBufferSequence& buffers,
                   boost::system::error_code& ec) {
    return out.write_some(buffers, ec);
  }
  template <typename MutableBufferSequence, typename ReadHandler>
  auto async_read_some(const MutableBufferSequence& buffers,
                       ReadHandler&& token) {
    return in.async_read_some(buffers, std::forward<ReadHandler>(token));
  }
  template <typename ConstBufferSequence, typename WriteHandler>
  auto async_write_some(const ConstBufferSequence& buffers,
                        WriteHandler&& token) {
    return out.async_write_some(buffers, std::forward<WriteHandler>(token));
  }
};

template <typename ReadStream, typename WriteStream>
auto join_streams(ReadStream&& in, WriteStream&& out)
{
  return joined_stream(std::forward<ReadStream>(in),
                       std::forward<WriteStream>(out));
}

} // namespace nexus::test
