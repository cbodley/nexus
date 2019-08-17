#pragma once

#include <nexus/quic/detail/connection_id.hpp>
#include <nexus/quic/detail/encoding/string.hpp>

namespace nexus::quic::detail {

using connection_id_encoder = length_prefix_string_encoder<uint8_t>;
using connection_id_decoder = length_prefix_string_decoder<uint8_t>;

} // namespace nexus::quic::detail
