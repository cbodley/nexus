#include <nexus/http2/basic_stream.hpp>
#include <nexus/http2/basic_connection.hpp>
#include <echo_stream.hpp>
#include <joined_stream.hpp>
#include <thread>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/http.hpp>
#include <gtest/gtest.h>

namespace nexus::http2 {

static const boost::system::error_code ok;

namespace http = boost::beast::http;

TEST(BasicStream, message)
{
  boost::asio::io_context ioctx;
  test::echo_stream in{ioctx.get_executor()};
  test::echo_stream out{ioctx.get_executor()};
  using joined_stream = test::joined_stream<decltype(in), decltype(out)>;

  // basic_connection as client
  basic_connection<joined_stream> client{client_tag, protocol::default_settings,
                                         in, out};
  std::thread client_read_thread([&client] {
      basic_stream stream{client};
      http::request<http::string_body, basic_fields<>> req;
      boost::system::error_code ec;
      stream.read(req, ec);
      ASSERT_EQ(ok, ec);
    });
  std::thread client_run_thread([&] {
      boost::system::error_code ec;
      client.run(ec);
      ASSERT_EQ(boost::asio::error::eof, ec);
    });
  // raw server
  {
    auto server = test::join_streams(out, in);

    // send headers frame
    constexpr uint8_t flags = protocol::frame_flag_end_stream |
                              protocol::frame_flag_end_headers;
    boost::system::error_code ec;
    detail::write_frame(server, protocol::frame_type::headers, flags, 2,
                        boost::asio::buffer("", 0), ec);
    ASSERT_EQ(ok, ec);
    in.close();
  };

  ioctx.run();
  client_read_thread.join();
  client_run_thread.join();
}

} // namespace nexus::http2
