#include <nexus/http2/basic_connection.hpp>
#include <thread>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/http/fields.hpp>
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
  using basic_connection<Stream>::send_priority;

  const detail::stream_impl* get_stream(protocol::stream_identifier id) const {
    auto stream = this->streams.find(id, detail::stream_id_less{});
    if (stream == this->streams.end()) {
      return nullptr;
    }
    return &*stream;
  }
};

TEST(BasicConnectionPriority, client)
{
  boost::asio::io_context ioctx;

  auto acceptor = start_listener(ioctx);
  auto port = acceptor.local_endpoint().port();

  // basic_connection as client
  std::thread thread([&] {
      test_basic_connection<tcp::socket> client{client_tag, protocol::default_settings, ioctx};

      boost::system::error_code ec;
      auto addr = boost::asio::ip::make_address("127.0.0.1");
      client.next_layer().connect(tcp::endpoint(addr, port), ec);
      ASSERT_EQ(ok, ec);
      client.send_priority(protocol::stream_priority{}, 1, ec);
      ASSERT_EQ(ok, ec);
      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);
    // read priority frame
    std::string frame(14, '\0');
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x5\x2\0\0\0\0\1\0\0\0\0\xf", 14), frame);
    ASSERT_EQ(ok, ec);
    server.shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionPriority, server)
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
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      const auto stream1 = server.get_stream(1);
      ASSERT_NE(nullptr, stream1);
      EXPECT_EQ(protocol::stream_state::idle, stream1->state);
      EXPECT_EQ(0u, stream1->priority.dependency);
      EXPECT_EQ(false, stream1->priority.exclusive);
      EXPECT_EQ(0u, stream1->priority.weight);
      EXPECT_EQ(nullptr, server.get_stream(2));
      const auto stream3 = server.get_stream(3);
      ASSERT_NE(nullptr, stream3);
      EXPECT_EQ(protocol::stream_state::idle, stream3->state);
      EXPECT_EQ(1u, stream3->priority.dependency);
      EXPECT_EQ(true, stream3->priority.exclusive);
      EXPECT_EQ(255u, stream3->priority.weight);
      server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw client
  {
    tcp::socket client{ioctx};

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), ec);
    ASSERT_EQ(ok, ec);
    detail::write_frame(client, protocol::frame_type::priority, 0, 1,
                        boost::asio::buffer("\0\0\0\0\0", 5), ec);
    ASSERT_EQ(ok, ec);
    detail::write_frame(client, protocol::frame_type::priority, 0, 3,
                        boost::asio::buffer("\x80\0\0\x1\xff", 5), ec);
    ASSERT_EQ(ok, ec);
    client.shutdown(tcp::socket::shutdown_both, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
