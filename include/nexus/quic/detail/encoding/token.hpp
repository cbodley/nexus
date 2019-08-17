#pragma once

#include <nexus/quic/detail/encoding/string.hpp>

namespace nexus::quic::detail {

using token_encoder = varint_prefix_string_encoder;
using token_decoder = varint_prefix_string_decoder;

} // namespace nexus::quic::detail
