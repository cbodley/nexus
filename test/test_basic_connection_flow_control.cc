#include <http2/basic_connection.hpp>
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

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
  using basic_connection<Stream>::send_window_update;
  using basic_connection<Stream>::adjust_outbound_window;

  protocol::flow_control_ssize_type get_outbound_window() const {
    return this->peer.window;
  }
};

TEST(BasicConnectionFlowControl, client)
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
      client.send_window_update(0, 1024, ec);
      ASSERT_EQ(ok, ec);
      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);

    // read window update frame
    std::string frame(13, '\0');
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x4\x8\0\0\0\0\0\0\0\x4\0", 13), frame);
    ASSERT_EQ(ok, ec);

    server.shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionFlowControl, server)
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
      // simulate writing entire window
      server.adjust_outbound_window(-65535, ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ(0, server.get_outbound_window());
      // run until eof
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      EXPECT_EQ(-0x7fff, server.get_outbound_window());
      server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw client
  {
    tcp::socket client{ioctx};

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), ec);
    ASSERT_EQ(ok, ec);
    // write settings with initial_window_size=0
    detail::write_frame(client, protocol::frame_type::settings, 0, 0,
                        boost::asio::buffer("\0\x4\0\0\0\0", 6), ec);
    // write window_update with increment=0x8000
    detail::write_frame(client, protocol::frame_type::window_update, 0, 0,
                        boost::asio::buffer("\0\0\x80\x00", 4), ec);
    client.shutdown(tcp::socket::shutdown_both, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
