#include <http2/client_connection.hpp>
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

TEST(ClientConnection, upgrade)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // client
  std::thread thread([&] {
      client_connection<tcp::socket> client{protocol::default_settings, ioctx};

      boost::system::error_code connect_ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.next_layer().connect(tcp::endpoint(addr, port), connect_ec);
      ASSERT_EQ(ok, connect_ec);

      boost::system::error_code upgrade_ec;
      client.upgrade("127.0.0.1", "/", upgrade_ec);
      ASSERT_EQ(ok, upgrade_ec);

      boost::system::error_code shutdown_ec;
      client.next_layer().shutdown(tcp::socket::shutdown_both, shutdown_ec);
    });
  // server
  {
    tcp::socket server{ioctx};

    boost::system::error_code accept_ec;
    acceptor.accept(server, accept_ec);
    ASSERT_EQ(ok, accept_ec);

    // read preface
    std::string preface(protocol::client_connection_preface.size(), '\0');
    boost::system::error_code preface_ec;
    boost::asio::read(server, boost::asio::buffer(preface), preface_ec);
    ASSERT_EQ(ok, preface_ec);
    EXPECT_EQ(protocol::client_connection_preface, preface);

    boost::system::error_code shutdown_ec;
    server.shutdown(tcp::socket::shutdown_both, shutdown_ec);
  }

  ioctx.run();
  thread.join();
}

} // namespace http2
