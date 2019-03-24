#include <http2/basic_connection.hpp>
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
  using basic_connection<Stream>::send_data;

  void open_stream(protocol::stream_identifier id) {
    auto impl = std::make_unique<detail::stream_impl>();
    impl->id = id;
    impl->state = protocol::stream_state::open;
    impl->inbound_window = this->self.settings.initial_window_size;
    impl->outbound_window = this->peer.settings.initial_window_size;
    this->streams.insert(this->streams.end(), *impl.release());
  }
  const detail::stream_impl* get_stream(protocol::stream_identifier id) const {
    auto stream = this->streams.find(id, detail::stream_id_less{});
    if (stream == this->streams.end()) {
      return nullptr;
    }
    return &*stream;
  }
  protocol::flow_control_ssize_type get_inbound_window() const {
    return this->self.window;
  }
  protocol::flow_control_ssize_type get_outbound_window() const {
    return this->peer.window;
  }
};

TEST(BasicConnectionData, client)
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
      client.open_stream(1);
      client.send_data(boost::asio::buffer("abc", 3), 1, ec);
      // adjust connection and stream flow control window
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                client.get_outbound_window());
      auto stream1 = client.get_stream(1);
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                stream1->outbound_window);
      ASSERT_EQ(ok, ec);
      client.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw server
  {
    tcp::socket server{ioctx};

    boost::system::error_code ec;
    acceptor.accept(server, ec);
    ASSERT_EQ(ok, ec);
    // read data frame
    std::string frame(12, '\0');
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x3\0\0\0\0\0\1abc", 12), frame);
    ASSERT_EQ(ok, ec);
    server.shutdown(tcp::socket::shutdown_both, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionData, server)
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
      server.open_stream(1);
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      const auto stream1 = server.get_stream(1);
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                server.get_inbound_window());
      ASSERT_NE(nullptr, stream1);
      EXPECT_EQ(protocol::stream_state::open, stream1->state);
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                stream1->inbound_window);
      EXPECT_EQ(nullptr, server.get_stream(2));
      server.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    });
  // raw client
  {
    tcp::socket client{ioctx};

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address("127.0.0.1");
    client.connect(tcp::endpoint(addr, port), ec);
    ASSERT_EQ(ok, ec);
    detail::write_frame(client, protocol::frame_type::data, 0, 1,
                        boost::asio::buffer("abc", 3), ec);
    ASSERT_EQ(ok, ec);
    client.shutdown(tcp::socket::shutdown_both, ec);
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
