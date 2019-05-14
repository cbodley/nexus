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
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as client
  std::thread thread([&] {
      test_basic_connection<joined_stream> client{client_tag, protocol::default_settings,
                                                  in, out};

      boost::system::error_code ec;
      client.send_priority(protocol::stream_priority{}, 1, ec);
      ASSERT_EQ(ok, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // read priority frame
    std::string frame(14, '\0');
    boost::system::error_code ec;
    boost::asio::read(server, boost::asio::buffer(frame), ec);
    ASSERT_EQ(ok, ec);
    EXPECT_EQ(std::string_view("\0\0\x5\x2\0\0\0\0\1\0\0\0\0\xf", 14), frame);
    ASSERT_EQ(ok, ec);
  }

  ioctx.run();
  thread.join();
}

TEST(BasicConnectionPriority, server)
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
    });
  // raw client
  {
    auto client = test::join_streams(out, in);

    boost::system::error_code ec;
    detail::write_frame(client, protocol::frame_type::priority, 0, 1,
                        boost::asio::buffer("\0\0\0\0\0", 5), ec);
    ASSERT_EQ(ok, ec);
    detail::write_frame(client, protocol::frame_type::priority, 0, 3,
                        boost::asio::buffer("\x80\0\0\x1\xff", 5), ec);
    ASSERT_EQ(ok, ec);
    in.close();
  }
  ioctx.run();
  thread.join();
}

} // namespace nexus::http2
