#include <nexus/http2/basic_stream.hpp>
#include <nexus/http2/basic_connection.hpp>
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/http.hpp>
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

TEST(BasicStream, message)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // basic_connection as client
  basic_connection<tcp::socket> client{client_tag, protocol::default_settings, ioctx};
  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address("127.0.0.1");
  client.next_layer().connect(tcp::endpoint(addr, port), ec);
  ASSERT_EQ(ok, ec);

  std::thread client_read_thread([&client] {
      basic_stream stream{client};
      boost::beast::http::request<boost::beast::http::string_body> req;
      boost::system::error_code ec;
      stream.read(req, ec);
      ASSERT_EQ(ok, ec);
    });
  std::thread client_run_thread([&] {
      boost::system::error_code ec;
      client.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);
    // send headers frame
    constexpr uint8_t flags = protocol::frame_flag_end_stream |
                              protocol::frame_flag_end_headers;
    detail::write_frame(server, protocol::frame_type::headers, flags, 2,
                        boost::asio::buffer("", 0), ec);
    ASSERT_EQ(ok, ec);
    server.shutdown(tcp::socket::shutdown_both, ec);
  };

  ioctx.run();
  client_read_thread.join();
  client_run_thread.join();
}

} // namespace nexus::http2
