#pragma once

#include <string>
#include <http2/detail/buffer.hpp>
#include <boost/system/system_error.hpp>

// url/filename-safe base64 encoding from RFC4648 without padding
namespace nexus::http2::detail::base64url {

inline constexpr char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

template <typename InputIterator, typename OutputIterator>
inline void encode3(InputIterator& in, OutputIterator& out)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto c1 = static_cast<uint8_t>(*in++);
  auto c2 = static_cast<uint8_t>(*in++);
  auto i0 = c0 >> 2;
  auto i1 = ((c0 << 4) & 0x3f) | (c1 >> 4);
  auto i2 = ((c1 << 2) & 0x3f) | (c2 >> 6);
  auto i3 = c2 & 0x3f;
  *out++ = alphabet[i0];
  *out++ = alphabet[i1];
  *out++ = alphabet[i2];
  *out++ = alphabet[i3];
}

template <typename InputIterator, typename OutputIterator>
inline void encode2(InputIterator& in, OutputIterator& out)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto c1 = static_cast<uint8_t>(*in++);
  auto i0 = c0 >> 2;
  auto i1 = ((c0 << 4) & 0x3f) | (c1 >> 4);
  auto i2 = ((c1 << 2) & 0x3f);
  *out++ = alphabet[i0];
  *out++ = alphabet[i1];
  *out++ = alphabet[i2];
}

template <typename InputIterator, typename OutputIterator>
inline void encode1(InputIterator& in, OutputIterator& out)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto i0 = c0 >> 2;
  auto i1 = ((c0 << 4) & 0x3f);
  *out++ = alphabet[i0];
  *out++ = alphabet[i1];
}

template <typename ConstBufferSequence, typename DynamicBuffer>
auto encode(const ConstBufferSequence& input, DynamicBuffer& output)
  -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence> &&
                      is_dynamic_buffer_v<DynamicBuffer>>
{
  const auto inlen = boost::asio::buffer_size(input);
  const auto outlen = (inlen + 2) / 3 * 4;
  auto out = boost::asio::buffers_begin(output.prepare(outlen));
  auto in = boost::asio::buffers_begin(input);

  auto remaining = inlen;
  while (remaining >= 3) {
    encode3(in, out);
    remaining -= 3;
  }
  switch (remaining) {
    case 2:
      encode2(in, out);
      output.commit(outlen - 1);
      break;
    case 1:
      encode1(in, out);
      output.commit(outlen - 2);
      break;
    default:
      output.commit(outlen);
      break;
  }
}

std::string encode(std::string_view input)
{
  std::string output;
  auto out = boost::asio::dynamic_buffer(output);
  encode(boost::asio::buffer(input.data(), input.size()), out);
  return output;
}

// decode error codes
enum class error {
  no_error = 0,
  invalid_length,
  invalid_character,
};

inline const boost::system::error_category& error_category()
{
  struct category : public boost::system::error_category {
    const char* name() const noexcept override {
      return "base64url";
    }
    std::string message(int ev) const override {
      switch (static_cast<error>(ev)) {
        case error::no_error:
          return "success";
        case error::invalid_length:
          return "invalid length";
        case error::invalid_character:
          return "invalid character";
        default:
          return "unknown";
      }
    }
  };
  static category instance;
  return instance;
}

inline boost::system::error_code make_error_code(error e)
{
  return {static_cast<int>(e), error_category()};
}

inline boost::system::error_condition make_error_condition(error e)
{
  return {static_cast<int>(e), error_category()};
}

} // namespace nexus::http2::detail::base64url

namespace boost::system {

/// enables implicit conversion to boost::system::error_condition
template <>
struct is_error_condition_enum<nexus::http2::detail::base64url::error> : public std::true_type {};

} // namespace boost::system

namespace nexus::http2::detail::base64url {

// map ascii characters back to their index in alphabet
inline constexpr uint8_t reverse_alphabet[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 16
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 32
  255,255,255,255,255,255,255,255,255,255,255,255,255, 62,255,255, // 48
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,255,255,255, // 64
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 80
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255, 63, // 96
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 112
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255, // 128
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 144
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 160
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 176
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 192
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 208
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 224
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 240
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 256
};

template <typename InputIterator, typename OutputIterator>
inline void decode4(InputIterator& in, OutputIterator& out,
                    boost::system::error_code& ec)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto c1 = static_cast<uint8_t>(*in++);
  auto c2 = static_cast<uint8_t>(*in++);
  auto c3 = static_cast<uint8_t>(*in++);
  auto i0 = reverse_alphabet[c0];
  auto i1 = reverse_alphabet[c1];
  auto i2 = reverse_alphabet[c2];
  auto i3 = reverse_alphabet[c3];
  if (0xc0 & (i0 | i1 | i2 | i3)) { // at least one invalid index
    ec = make_error_code(error::invalid_character);
  } else {
    *out++ = (i0 << 2) + (i1 >> 4);
    *out++ = (i1 << 4) + (i2 >> 2);
    *out++ = (i2 << 6) + i3;
  }
}

template <typename InputIterator, typename OutputIterator>
inline void decode3(InputIterator& in, OutputIterator& out,
                    boost::system::error_code& ec)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto c1 = static_cast<uint8_t>(*in++);
  auto c2 = static_cast<uint8_t>(*in++);
  auto i0 = reverse_alphabet[c0];
  auto i1 = reverse_alphabet[c1];
  auto i2 = reverse_alphabet[c2];
  if (0xc0 & (i0 | i1 | i2)) { // at least one invalid index
    ec = make_error_code(error::invalid_character);
  } else {
    *out++ = (i0 << 2) + (i1 >> 4);
    *out++ = (i1 << 4) + (i2 >> 2);
    *out++ = (i2 << 6);
  }
}

template <typename InputIterator, typename OutputIterator>
inline void decode2(InputIterator& in, OutputIterator& out,
                    boost::system::error_code& ec)
{
  auto c0 = static_cast<uint8_t>(*in++);
  auto c1 = static_cast<uint8_t>(*in++);
  auto i0 = reverse_alphabet[c0];
  auto i1 = reverse_alphabet[c1];
  if (0xc0 & (i0 | i1)) { // at least one invalid index
    ec = make_error_code(error::invalid_character);
  } else {
    *out++ = (i0 << 2) + (i1 >> 4);
    *out++ = (i1 << 4);
  }
}

template <typename ConstBufferSequence, typename DynamicBuffer>
auto decode(const ConstBufferSequence& input, DynamicBuffer& output,
            boost::system::error_code& ec)
  -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence> &&
                      is_dynamic_buffer_v<DynamicBuffer>>
{
  const auto inlen = boost::asio::buffer_size(input);
  const auto outlen = (inlen + 3) / 4 * 3;
  auto out = boost::asio::buffers_begin(output.prepare(outlen));
  auto in = boost::asio::buffers_begin(input);

  auto remaining = inlen;
  while (remaining >= 4) {
    decode4(in, out, ec);
    if (ec) {
      return;
    }
    remaining -= 4;
  }
  switch (remaining) {
    case 3:
      decode3(in, out, ec);
      output.commit(outlen - 1);
      break;
    case 2:
      decode2(in, out, ec);
      output.commit(outlen - 2);
      break;
    case 1:
      ec = make_error_code(error::invalid_length);
      output.commit(0);
      break;
    default:
      output.commit(outlen);
      break;
  }
}

template <typename ConstBufferSequence, typename DynamicBuffer>
auto decode(const ConstBufferSequence& input, DynamicBuffer& output)
  -> std::enable_if_t<is_const_buffer_sequence_v<ConstBufferSequence> &&
                      is_dynamic_buffer_v<DynamicBuffer>>
{
  boost::system::error_code ec;
  decode(input, output, ec);
  if (ec) {
    throw boost::system::system_error(ec);
  }
}

std::string decode(std::string_view input, boost::system::error_code& ec)
{
  std::string output;
  auto out = boost::asio::dynamic_buffer(output);
  decode(boost::asio::buffer(input.data(), input.size()), out, ec);
  return output;
}

std::string decode(std::string_view input)
{
  boost::system::error_code ec;
  auto output = decode(input, ec);
  if (ec) {
    throw boost::system::system_error(ec);
  }
  return output;
}

} // namespace nexus::http2::detail::base64url
