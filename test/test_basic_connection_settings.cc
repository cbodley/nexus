#include <nexus/http2/basic_connection.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <thread>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

template <typename Stream>
class test_basic_connection : public basic_connection<Stream> {
 public:
  using basic_connection<Stream>::basic_connection;
  using basic_connection<Stream>::send_settings;

  const protocol::setting_values& get_settings() const {
    return this->self.settings;
  }
  const protocol::setting_values& get_peer_settings() const {
    return this->peer.settings;
  }
};

TEST(BasicConnectionSettings, client)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as client
  std::thread thread([&] {
      auto settings = protocol::default_settings;
      settings.max_frame_size = protocol::max_setting_max_frame_size;
      test_basic_connection<joined_stream> client{client_tag, settings, in, out};

      boost::system::error_code ec;
      client.send_settings(ec);
      ASSERT_EQ(ok, ec);
      // run until eof
      client.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      // must have gotten ack
      EXPECT_EQ(protocol::max_setting_max_frame_size,
                client.get_settings().max_frame_size);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // read settings frame
    std::string frame(15, '\0');
    boost::system::error_code ec;
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\6\4\0\0\0\0\0\0\5\0\xff\xff\xff", 15), frame);
    // send settings ack
    constexpr auto type = protocol::frame_type::settings;
    constexpr auto flags = protocol::frame_flag_ack;
    constexpr protocol::stream_identifier stream_id = 0;
    auto payload = boost::asio::const_buffer(); // empty
    detail::write_frame(server, type, flags, stream_id, payload, ec);
    ASSERT_EQ(ok, ec);
    in.close();
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionSettings, server)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as server
  std::thread thread([&] {
      test_basic_connection<joined_stream> server{server_tag, protocol::default_settings,
                                                  in, out};
      // run until eof
      boost::system::error_code ec;
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      // must have applied client settings
      EXPECT_EQ(protocol::max_setting_max_frame_size,
                server.get_peer_settings().max_frame_size);
    });
  // raw client
  {
    auto client = test::join_streams(out, in);

    auto settings = boost::asio::buffer("\0\0\6\4\0\0\0\0\0\0\5\0\xff\xff\xff", 15);
    boost::system::error_code ec;
    boost::asio::write(client, settings, ec);
    ASSERT_EQ(ok, ec);
    // read settings ack
    protocol::frame_header header;
    detail::read_frame_header(client, header, ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(0u, header.length);
    EXPECT_EQ(protocol::frame_type::settings, static_cast<protocol::frame_type>(header.type));
    EXPECT_EQ(protocol::frame_flag_ack, header.flags);
    EXPECT_EQ(0u, header.stream_id);
    in.close();
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
