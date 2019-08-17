#pragma once

#include <iterator>
#include <type_traits>
#include <boost/asio/buffers_iterator.hpp>

namespace nexus::detail {

template <typename Arg1, typename ...Args>
size_t encoded_size(const Arg1& arg1, const Args& ...args)
{
  return encoded_size(arg1) + (encoded_size(args) + ...);
}

template <typename OutputIterator, typename Arg1, typename ...Args>
void encode1(OutputIterator& out, Arg1&& arg1, Args&& ...args)
{
  encode(out, std::forward<Arg1>(arg1));
  (encode(out, std::forward<Args>(args)), ...);
}

struct encoded_size_mismatch : std::runtime_error {
  using std::runtime_error::runtime_error;
};

template <typename DynamicBuffer, typename Arg1, typename ...Args>
size_t encode2(DynamicBuffer& buffers, Arg1&& arg1, Args&& ...args)
{
  const size_t length = encoded_size(arg1, args...);
  auto data = buffers.prepare(length);
  auto out = boost::asio::buffers_begin(data);
  encode1(out, std::forward<Arg1>(arg1), std::forward<Args>(args)...);
  if (out != boost::asio::buffers_end(data)) {
    throw encoded_size_mismatch{"encode2 size mismatch"};
  }
  buffers.commit(length);
  return length;
}

template <typename InputIterator, typename Arg1, typename Arg2, typename ...Args>
bool decode(InputIterator& in, size_t& remaining,
            Arg1&& arg1, Arg2&& arg2, Args&& ...args)
{
  return decode(in, remaining, std::forward<Arg1>(arg1))
      && decode(in, remaining, std::forward<Arg2>(arg2))
      && (decode(in, remaining, std::forward<Args>(args)) && ...);
}

} // namespace nexus::detail
