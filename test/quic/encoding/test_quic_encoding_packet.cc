#include <nexus/quic/detail/encoding/packet.hpp>
#include <vector>
#include <gtest/gtest.h>

namespace nexus::quic::detail {

TEST(quic_encoding, packet_header)
{
  std::vector<uint8_t> encoded;
  {
    long_header header;
    header.version = 1;
    header.destination = "bob";
    header.source = "alice";

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode_header(0xc0, header, buffer);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    uint8_t head = 0;
    ASSERT_TRUE(decode_head(head, pos, remaining));
    EXPECT_EQ(0xc0, head);

    long_header header;
    ASSERT_TRUE(decode_header(header, pos, remaining));
    EXPECT_EQ(0, remaining);
    EXPECT_EQ(1, header.version);
    EXPECT_EQ("bob", header.destination);
    EXPECT_EQ("alice", header.source);
  }
}

TEST(quic_encoding, initial_packet)
{
  std::vector<uint8_t> encoded;
  {
    initial_packet packet;
    packet.token = "foo";
    packet.packet_number = 0;
    packet.payload_length = 0;

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode_packet(packet, buffer);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);
    initial_packet packet;
    ASSERT_TRUE(decode_packet(packet, 1, pos, remaining));
    EXPECT_EQ(0, remaining);
    EXPECT_EQ("foo", packet.token);
    EXPECT_EQ(0, packet.packet_number);
    EXPECT_EQ(0, packet.payload_length);
  }
}

TEST(quic_encoding, zero_rtt_packet)
{
  std::vector<uint8_t> encoded;
  {
    zero_rtt_packet packet;
    packet.packet_number = 0;
    packet.payload_length = 0;

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode_packet(packet, buffer);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);
    zero_rtt_packet packet;
    ASSERT_TRUE(decode_packet(packet, 1, pos, remaining));
    EXPECT_EQ(0, remaining);
    EXPECT_EQ(0, packet.packet_number);
    EXPECT_EQ(0, packet.payload_length);
  }
}

TEST(quic_encoding, handshake_packet)
{
  std::vector<uint8_t> encoded;
  {
    handshake_packet packet;
    packet.packet_number = 0;
    packet.payload_length = 0;

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode_packet(packet, buffer);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);
    handshake_packet packet;
    ASSERT_TRUE(decode_packet(packet, 1, pos, remaining));
    EXPECT_EQ(0, remaining);
    EXPECT_EQ(0, packet.packet_number);
    EXPECT_EQ(0, packet.payload_length);
  }
}

TEST(quic_encoding, retry_packet)
{
  std::vector<uint8_t> encoded;
  {
    retry_packet packet;
    packet.original_destination = "tom";
    packet.retry_token = "applesauce";

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode_packet(packet, buffer);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);
    retry_packet packet;
    ASSERT_TRUE(decode_packet(packet, pos, remaining));
    EXPECT_EQ(0, remaining);
    EXPECT_EQ("tom", packet.original_destination);
    EXPECT_EQ("applesauce", packet.retry_token);
  }
}

} // namespace nexus::quic::detail
