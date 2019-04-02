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
  using basic_connection<Stream>::send_window_update;
  using basic_connection<Stream>::adjust_outbound_window;

  protocol::flow_control_ssize_type get_outbound_window() const {
    return this->peer.window;
  }
};

TEST(BasicConnectionFlowControl, client)
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
      client.send_window_update(0, 1024, ec);
      ASSERT_EQ(ok, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // read window update frame
    std::string frame(13, '\0');
    boost::system::error_code ec;
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x4\x8\0\0\0\0\0\0\0\x4\0", 13), frame);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionFlowControl, server)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as server
  std::thread thread([&] {
      test_basic_connection<joined_stream> server{server_tag, protocol::default_settings,
                                                  in, out};

      // simulate writing entire window
      boost::system::error_code ec;
      server.adjust_outbound_window(-65535, ec);
      ASSERT_EQ(ok, ec);
      EXPECT_EQ(0, server.get_outbound_window());
      // run until eof
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      EXPECT_EQ(-0x7fff, server.get_outbound_window());
    });
  // raw client
  {
    auto client = test::join_streams(out, in);

    // write settings with initial_window_size=0
    boost::system::error_code ec;
    detail::write_frame(client, protocol::frame_type::settings, 0, 0,
                        boost::asio::buffer("\0\x4\0\0\0\0", 6), ec);
    // write window_update with increment=0x8000
    detail::write_frame(client, protocol::frame_type::window_update, 0, 0,
                        boost::asio::buffer("\0\0\x80\x00", 4), ec);
    in.close();
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
