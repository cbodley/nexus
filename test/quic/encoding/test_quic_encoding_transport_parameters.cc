#include <nexus/quic/detail/encoding/transport_parameters.hpp>
#include <algorithm>
#include <vector>
#include <gtest/gtest.h>

namespace std {
template <typename T, size_t N>
bool operator==(const char str[N], const std::array<T, N>& arr)
{
  return std::equal(arr.begin(), arr.end(), str);
}
}

namespace nexus::quic::detail {

TEST(quic_encoding, transport_preferred_address)
{
  std::vector<uint8_t> encoded;
  {
    transport_preferred_address addr;
    std::copy_n("0123", 4, addr.addressv4.begin());
    addr.portv4 = 123;
    std::copy_n("0123456789abcdef", 16, addr.addressv6.begin());
    addr.portv6 = 234;
    addr.connection_id = "applesauce";
    addr.stateless_reset_token = "fedcba9876543210";

    std::back_insert_iterator out{encoded};
    encode(out, addr);
    ASSERT_EQ(51, encoded.size());
  }
  {
    transport_preferred_address decoded;
    size_t remaining = encoded.size();
    auto in = encoded.begin();
    ASSERT_TRUE(decode(in, remaining, decoded));
    EXPECT_EQ(encoded.end(), in);
    EXPECT_EQ(0, remaining);

    EXPECT_EQ("0123", decoded.addressv4);
    EXPECT_EQ(123, decoded.portv4);
    EXPECT_EQ("0123456789abcdef", decoded.addressv6);
    EXPECT_EQ(234, decoded.portv6);
    EXPECT_EQ("applesauce", decoded.connection_id);
    EXPECT_EQ("fedcba9876543210", decoded.stateless_reset_token);
  }
}

TEST(quic_encoding, transport_parameters)
{
  std::vector<uint8_t> encoded;
  {
    transport_parameters params = {};
    transport_parameter_mask_t mask = 0;

    mask.set(static_cast<size_t>(transport_parameter_id::original_connection_id));
    params.original_connection_id = "alice";
    mask.set(static_cast<size_t>(transport_parameter_id::idle_timeout));
    params.idle_timeout = std::chrono::hours(1);
    mask.set(static_cast<size_t>(transport_parameter_id::initial_max_data));
    params.initial_max_data = 1;
    // don't set mask for ack_delay_exponent
    params.ack_delay_exponent = 4;
    mask.set(static_cast<size_t>(transport_parameter_id::active_connection_id_limit));
    params.active_connection_id_limit = varint_max;

    std::back_insert_iterator out{encoded};
    encode(out, transport_parameters_encoder{params, mask});
    ASSERT_EQ(36, encoded.size());
  }
  {
    transport_parameters decoded = {};
    transport_parameter_mask_t mask = 0;
    size_t remaining = encoded.size();
    auto in = encoded.begin();
    ASSERT_TRUE(decode(in, remaining, transport_parameters_decoder{decoded, mask}));
    EXPECT_EQ(encoded.end(), in);
    EXPECT_EQ(0, remaining);

    EXPECT_EQ("alice", decoded.original_connection_id);
    EXPECT_EQ(std::chrono::hours(1), decoded.idle_timeout);
    EXPECT_EQ(1, decoded.initial_max_data);
    EXPECT_EQ(0, decoded.ack_delay_exponent);
    EXPECT_EQ(varint_max, decoded.active_connection_id_limit);
  }
}

} // namespace nexus::quic::detail
