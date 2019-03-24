#include <http2/detail/settings.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

TEST(Settings, copy)
{
  protocol::setting_parameters params;
  ASSERT_EQ(params.end(), protocol::detail::copy(params.begin(), protocol::default_settings));
  EXPECT_EQ(1u, params[0].identifier);
  EXPECT_EQ(protocol::default_setting_header_table_size, params[0].value);
  EXPECT_EQ(2u, params[1].identifier);
  EXPECT_EQ(protocol::default_setting_enable_push, params[1].value);
  EXPECT_EQ(3u, params[2].identifier);
  EXPECT_EQ(protocol::default_setting_max_concurrent_streams, params[2].value);
  EXPECT_EQ(4u, params[3].identifier);
  EXPECT_EQ(protocol::default_setting_initial_window_size, params[3].value);
  EXPECT_EQ(5u, params[4].identifier);
  EXPECT_EQ(protocol::default_setting_max_frame_size, params[4].value);
  EXPECT_EQ(6u, params[5].identifier);
  EXPECT_EQ(protocol::default_setting_max_header_list_size, params[5].value);
}

TEST(Settings, copy_changes)
{
  protocol::setting_parameters params;
  ASSERT_EQ(params.begin(), protocol::detail::copy_changes(params.begin(),
                                                           protocol::default_settings,
                                                           protocol::default_settings));
  protocol::setting_values zeroes = {0, 0, 0, 0, 0, 0};
  ASSERT_EQ(params.end(), protocol::detail::copy_changes(params.begin(),
                                                         protocol::default_settings,
                                                         zeroes));
  EXPECT_EQ(1u, params[0].identifier);
  EXPECT_EQ(0u, params[0].value);
  EXPECT_EQ(2u, params[1].identifier);
  EXPECT_EQ(0u, params[1].value);
  EXPECT_EQ(3u, params[2].identifier);
  EXPECT_EQ(0u, params[2].value);
  EXPECT_EQ(4u, params[3].identifier);
  EXPECT_EQ(0u, params[3].value);
  EXPECT_EQ(5u, params[4].identifier);
  EXPECT_EQ(0u, params[4].value);
  EXPECT_EQ(6u, params[5].identifier);
  EXPECT_EQ(0u, params[5].value);
}

TEST(Settings, encode)
{
  std::string encoded;
  auto buffers = boost::asio::dynamic_buffer(encoded);
  const auto size = sizeof(uint16_t) + sizeof(uint32_t);
  auto buf = buffers.prepare(size);
  auto pos = boost::asio::buffers_begin(buf);
  pos = protocol::detail::encode_setting({0x0102, 0x03040506}, pos);
  ASSERT_EQ(boost::asio::buffers_end(buf), pos);
  buffers.commit(size);
  ASSERT_EQ(6u, encoded.size());
  EXPECT_EQ("\x1\x2\x3\x4\x5\x6", encoded);
}

TEST(Settings, decode)
{
  uint8_t encoded[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
  auto buf = boost::asio::buffer(encoded);
  auto pos = boost::asio::buffers_begin(buf);
  protocol::setting_parameter_pair param;
  pos = protocol::detail::decode_setting(pos, param);
  ASSERT_EQ(boost::asio::buffers_end(buf), pos);
  EXPECT_EQ(0x0102, param.identifier);
  EXPECT_EQ(0x03040506, param.value);
}

} // namespace nexus::http2
