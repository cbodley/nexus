#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/buffers_iterator.hpp>

namespace nexus::http2::detail {

template <typename T>
constexpr bool is_mutable_buffer_sequence_v =
    boost::asio::is_mutable_buffer_sequence<T>::value;
template <typename T>
constexpr bool is_const_buffer_sequence_v =
    boost::asio::is_const_buffer_sequence<T>::value;
template <typename T>
constexpr bool is_dynamic_buffer_v =
    boost::asio::is_dynamic_buffer<T>::value;

} // namespace nexus::http2::detail
