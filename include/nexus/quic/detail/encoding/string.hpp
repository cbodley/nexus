#pragma once

#include <nexus/detail/encoding/string.hpp>
#include <nexus/detail/encoding/length_prefix.hpp>
#include <nexus/detail/encoding/network_order.hpp>
#include <nexus/quic/detail/encoding/varint.hpp>

namespace nexus::quic::detail {

using nexus::detail::string_encoder;
using nexus::detail::string_decoder;

using nexus::detail::network_order_encoder;
using nexus::detail::network_order_decoder;

using nexus::detail::length_prefix_encoder;
using nexus::detail::length_prefix_decoder;

// string encoding with a fixed-size network-order length prefix
template <typename Unsigned>
using length_prefix_string_encoder = length_prefix_encoder<
    network_order_encoder<Unsigned>, string_encoder>;

template <typename Unsigned>
using length_prefix_string_decoder = length_prefix_decoder<
    Unsigned, network_order_decoder<Unsigned>, string_decoder, std::string>;

// string encoding with a varint length prefix
using varint_prefix_string_encoder = length_prefix_encoder<
    varint_encoder, string_encoder>;

using varint_prefix_string_decoder = length_prefix_decoder<
    varint_t, varint_decoder, string_decoder, std::string>;

} // namespace nexus::quic::detail
