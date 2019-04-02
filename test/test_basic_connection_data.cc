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
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as client
  std::thread thread([&] {
      test_basic_connection<joined_stream> client{client_tag, protocol::default_settings,
                                                  in, out};

      client.open_stream(1);
      boost::system::error_code ec;
      client.send_data(boost::asio::buffer("abc", 3), 1, ec);
      // adjust connection and stream flow control window
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                client.get_outbound_window());
      auto stream1 = client.get_stream(1);
      EXPECT_EQ(protocol::default_setting_initial_window_size - 3,
                stream1->outbound_window);
      ASSERT_EQ(ok, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // read data frame
    std::string frame(12, '\0');
    boost::system::error_code ec;
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x3\0\0\0\0\0\1abc", 12), frame);
    ASSERT_EQ(ok, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionData, server)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as server
  std::thread thread([&] {
      test_basic_connection<joined_stream> server{server_tag, protocol::default_settings,
                                                  in, out};

      server.open_stream(1);
      boost::system::error_code ec;
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
    });
  // raw client
  {
    auto client = test::join_streams(out, in);

    boost::system::error_code ec;
    detail::write_frame(client, protocol::frame_type::data, 0, 1,
                        boost::asio::buffer("abc", 3), ec);
    ASSERT_EQ(ok, ec);
    in.close();
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
