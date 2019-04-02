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
  using basic_connection<Stream>::send_ping;
};

TEST(BasicConnectionPing, client)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as client
  std::thread thread([&] {
      test_basic_connection<joined_stream> client{client_tag, protocol::default_settings,
                                                  in, out};

      boost::system::error_code ec;
      client.send_ping(boost::asio::buffer("12345678", 8), ec);
      ASSERT_EQ(ok, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // read ping frame
    std::string frame(17, '\0');
    boost::system::error_code ec;
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x8\x6\0\0\0\0\0"
                               "12345678", 17), frame);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionPing, server)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as server
  std::thread thread([&] {
      test_basic_connection<joined_stream> server{server_tag, protocol::default_settings,
                                                  in, out};
      boost::system::error_code ec;
      server.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
      out.close();
    });
  // raw client
  {
    auto client = test::join_streams(out, in);

    boost::system::error_code ec;
    detail::write_frame(client, protocol::frame_type::ping, 0, 0,
                        boost::asio::buffer("12345678", 8), ec);
    ASSERT_EQ(ok, ec);
    // read ping ack frame
    std::string frame(17, '\0');
    boost::asio::read(client, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x8\x6\x1\0\0\0\0"
                               "12345678", 17), frame);
    in.close();
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
