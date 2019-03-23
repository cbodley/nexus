#include <http2/basic_connection.hpp>
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace http2 {

static const boost::system::error_code ok;

using boost::asio::ip::tcp;
tcp::acceptor start_listener(boost::asio::io_context& ioctx)
{
  tcp::acceptor acceptor(ioctx);
  tcp::endpoint endpoint(tcp::v4(), 0);
  acceptor.open(endpoint.protocol());
  acceptor.bind(endpoint);
  acceptor.listen();
  return acceptor;
}

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

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // basic_connection as client
  std::thread thread([&] {
      auto settings = protocol::default_settings;
      settings.max_frame_size = protocol::max_setting_max_frame_size;
      test_basic_connection<tcp::socket> client{client_tag, settings, ioctx};

      boost::system::error_code ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.next_layer().connect(tcp::endpoint(addr, port), ec);
      ASSERT_EQ(ok, ec);

      client.send_settings(ec);
      ASSERT_EQ(ok, ec);
      // run until eof
      client.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      // must have gotten ack
      EXPECT_EQ(protocol::max_setting_max_frame_size,
                client.get_settings().max_frame_size);
      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);

    // read settings frame
    std::string frame(15, '\0');
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

    server.shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionSettings, server)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // basic_connection as server
  std::thread thread([&] {
      test_basic_connection<tcp::socket> server{server_tag, protocol::default_settings, ioctx};

      boost::system::error_code ec;
      acceptor.accept(server.next_layer(), ec);
      ASSERT_EQ(ok, ec);
      // run until eof
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      // must have applied client settings
      EXPECT_EQ(protocol::max_setting_max_frame_size,
                server.get_peer_settings().max_frame_size);

      server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw client
  {
    tcp::socket client{ioctx};

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), ec);
    ASSERT_EQ(ok, ec);

    auto settings = boost::asio::buffer("\0\0\6\4\0\0\0\0\0\0\5\0\xff\xff\xff", 15);
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

    client.shutdown(tcp::socket::shutdown_both, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace http2
