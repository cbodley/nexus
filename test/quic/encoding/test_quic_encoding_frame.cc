#include <nexus/quic/detail/encoding/frame.hpp>
#include <vector>
#include <boost/asio/buffers_iterator.hpp>
#include <gtest/gtest.h>

namespace nexus::quic::detail {

TEST(quic_encoding, ack_frame)
{
  std::vector<uint8_t> encoded;
  {
    const ack_frame ack{1234, 1, 2, 2};
    const ack_range ranges[] = {{1, 0}, {1, 0}};
    const ack_ecn_counts ecn{1, 2, 3};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, ack_ecn_frame_encoder{ack, std::begin(ranges),
                                          std::end(ranges), ecn});
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    ack_frame ack;
    ack_range ranges[2];
    ack_ecn_counts ecn;
    ASSERT_TRUE(decode(pos, remaining, ack_ecn_frame_decoder{ack, ranges, ecn}));
    EXPECT_EQ(1234u, ack.largest_acknowledged);
    EXPECT_EQ(1u, ack.ack_delay);
    EXPECT_EQ(2u, ack.ack_range_count);
    EXPECT_EQ(2u, ack.first_ack_range);
    EXPECT_EQ(1u, ranges[0].gap);
    EXPECT_EQ(0u, ranges[0].ack);
    EXPECT_EQ(1u, ranges[1].gap);
    EXPECT_EQ(0u, ranges[1].ack);
    EXPECT_EQ(1u, ecn.ect0);
    EXPECT_EQ(2u, ecn.ect1);
    EXPECT_EQ(3u, ecn.ce);
  }
}

TEST(quic_encoding, reset_stream_frame)
{
  std::vector<uint8_t> encoded;
  {
    const reset_stream_frame reset{1, 2, 3};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, reset);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    reset_stream_frame reset;
    ASSERT_TRUE(decode(pos, remaining, reset));
    EXPECT_EQ(1u, reset.stream_id);
    EXPECT_EQ(2u, reset.app_error_code);
    EXPECT_EQ(3u, reset.final_size);
  }
}

TEST(quic_encoding, stop_sending_frame)
{
  std::vector<uint8_t> encoded;
  {
    const stop_sending_frame stop{1, 2};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, stop);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    stop_sending_frame stop;
    ASSERT_TRUE(decode(pos, remaining, stop));
    EXPECT_EQ(1u, stop.stream_id);
    EXPECT_EQ(2u, stop.app_error_code);
  }
}

TEST(quic_encoding, crypto_frame)
{
  std::vector<uint8_t> encoded;
  {
    const crypto_frame crypto{1, 2};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, crypto);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    crypto_frame crypto;
    ASSERT_TRUE(decode(pos, remaining, crypto));
    EXPECT_EQ(1u, crypto.offset);
    EXPECT_EQ(2u, crypto.length);
  }
}

TEST(quic_encoding, new_token_frame)
{
  std::vector<uint8_t> encoded;
  {
    const new_token_frame token{"token"};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, token);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    new_token_frame token;
    ASSERT_TRUE(decode(pos, remaining, token));
    EXPECT_EQ("token", token.token);
  }
}

TEST(quic_encoding, stream_frame)
{
  const uint8_t has_both = stream_frame_off_bit | stream_frame_len_bit;
  const uint8_t has_off = stream_frame_off_bit;
  const uint8_t has_len = stream_frame_len_bit;

  std::vector<uint8_t> encoded;
  {
    const stream_frame stream{0, 1, 2};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, stream_frame_encoder{stream, has_both});
    encode2(buffer, stream_frame_encoder{stream, has_off});
    encode2(buffer, stream_frame_encoder{stream, has_len});
    encode2(buffer, stream_frame_encoder{stream, 0});
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);
    {
      stream_frame stream;
      ASSERT_TRUE(decode(pos, remaining, stream_frame_decoder{stream, has_both}));
      EXPECT_EQ(0u, stream.stream_id);
      EXPECT_EQ(1u, stream.offset);
      EXPECT_EQ(2u, stream.length);
    }
    {
      stream_frame stream;
      ASSERT_TRUE(decode(pos, remaining, stream_frame_decoder{stream, has_off}));
      EXPECT_EQ(0u, stream.stream_id);
      EXPECT_EQ(1u, stream.offset);
      EXPECT_EQ(0u, stream.length);
    }
    {
      stream_frame stream;
      ASSERT_TRUE(decode(pos, remaining, stream_frame_decoder{stream, has_len}));
      EXPECT_EQ(0u, stream.stream_id);
      EXPECT_EQ(0u, stream.offset);
      EXPECT_EQ(2u, stream.length);
    }
    {
      stream_frame stream;
      ASSERT_TRUE(decode(pos, remaining, stream_frame_decoder{stream, 0}));
      EXPECT_EQ(0u, stream.stream_id);
      EXPECT_EQ(0u, stream.offset);
      EXPECT_EQ(0u, stream.length);
    }
  }
}

TEST(quic_encoding, max_data_frame)
{
  std::vector<uint8_t> encoded;
  {
    const max_data_frame max_data{1};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, max_data);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    max_data_frame max_data;
    ASSERT_TRUE(decode(pos, remaining, max_data));
    EXPECT_EQ(1u, max_data.maximum_data);
  }
}

TEST(quic_encoding, max_stream_data_frame)
{
  std::vector<uint8_t> encoded;
  {
    const max_stream_data_frame max_data{1, 2};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, max_data);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    max_stream_data_frame max_data;
    ASSERT_TRUE(decode(pos, remaining, max_data));
    EXPECT_EQ(1u, max_data.stream_id);
    EXPECT_EQ(2u, max_data.maximum_data);
  }
}

TEST(quic_encoding, max_streams_frame)
{
  std::vector<uint8_t> encoded;
  {
    const max_streams_frame max_streams{1};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, max_streams);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    max_streams_frame max_streams;
    ASSERT_TRUE(decode(pos, remaining, max_streams));
    EXPECT_EQ(1u, max_streams.maximum_streams);
  }
}

TEST(quic_encoding, data_blocked_frame)
{
  std::vector<uint8_t> encoded;
  {
    const data_blocked_frame data_blocked{1};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, data_blocked);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    data_blocked_frame data_blocked;
    ASSERT_TRUE(decode(pos, remaining, data_blocked));
    EXPECT_EQ(1u, data_blocked.data_limit);
  }
}

TEST(quic_encoding, stream_data_blocked_frame)
{
  std::vector<uint8_t> encoded;
  {
    const stream_data_blocked_frame data_blocked{1, 2};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, data_blocked);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    stream_data_blocked_frame data_blocked;
    ASSERT_TRUE(decode(pos, remaining, data_blocked));
    EXPECT_EQ(1u, data_blocked.stream_id);
    EXPECT_EQ(2u, data_blocked.data_limit);
  }
}

TEST(quic_encoding, streams_blocked_frame)
{
  std::vector<uint8_t> encoded;
  {
    const streams_blocked_frame streams_blocked{1};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, streams_blocked);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    streams_blocked_frame streams_blocked;
    ASSERT_TRUE(decode(pos, remaining, streams_blocked));
    EXPECT_EQ(1u, streams_blocked.stream_limit);
  }
}

TEST(quic_encoding, new_connection_id_frame)
{
  std::vector<uint8_t> encoded;
  {
    const new_connection_id_frame new_connection_id{1, 2, "alice", "reset"};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, new_connection_id);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    new_connection_id_frame new_connection_id;
    ASSERT_TRUE(decode(pos, remaining, new_connection_id));
    EXPECT_EQ(1u, new_connection_id.sequence_number);
    EXPECT_EQ(2u, new_connection_id.retired_prior_to);
    EXPECT_EQ("alice", new_connection_id.connection_id);
    EXPECT_EQ("reset", new_connection_id.stateless_reset_token);
  }
}

TEST(quic_encoding, retire_connection_id_frame)
{
  std::vector<uint8_t> encoded;
  {
    const retire_connection_id_frame retire_connection_id{1};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, retire_connection_id);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    retire_connection_id_frame retire_connection_id;
    ASSERT_TRUE(decode(pos, remaining, retire_connection_id));
    EXPECT_EQ(1u, retire_connection_id.sequence_number);
  }
}

TEST(quic_encoding, path_challenge_frame)
{
  std::vector<uint8_t> encoded;
  {
    const path_challenge_frame path_challenge{"12345678"};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, path_challenge);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    path_challenge_frame path_challenge;
    ASSERT_TRUE(decode(pos, remaining, path_challenge));
    EXPECT_EQ("12345678", path_challenge.data);
  }
}

TEST(quic_encoding, path_response_frame)
{
  std::vector<uint8_t> encoded;
  {
    const path_response_frame path_response{"12345678"};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, path_response);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    path_response_frame path_response;
    ASSERT_TRUE(decode(pos, remaining, path_response));
    EXPECT_EQ("12345678", path_response.data);
  }
}

TEST(quic_encoding, connection_close_frame)
{
  std::vector<uint8_t> encoded;
  {
    const connection_close_frame connection_close{1, 2, "does not compute"};

    boost::asio::dynamic_vector_buffer buffer{encoded};
    encode2(buffer, connection_close);
  }
  {
    auto buffer = boost::asio::buffer(encoded);
    size_t remaining = encoded.size();
    auto pos = boost::asio::buffers_begin(buffer);

    connection_close_frame connection_close;
    ASSERT_TRUE(decode(pos, remaining, connection_close));
    EXPECT_EQ(1u, connection_close.error_code);
    EXPECT_EQ(2u, connection_close.frame_type);
    EXPECT_EQ("does not compute", connection_close.reason_phrase);
  }
}

} // namespace nexus::quic::detail
