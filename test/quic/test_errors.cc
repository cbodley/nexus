#include <nexus/quic/error.hpp>
#include <gtest/gtest.h>

namespace nexus::quic {

TEST(errors, connection)
{
  // connection errors are distinguishable from stream errors
  EXPECT_NE(make_error_condition(error::stream_aborted),
            make_error_code(error::connection_aborted));
  // connection errors can be compared to generic error conditions
  EXPECT_EQ(make_error_condition(errc::connection_reset),
            make_error_code(error::connection_reset));
  EXPECT_EQ(make_error_condition(errc::connection_aborted),
            make_error_code(error::connection_aborted));
}

TEST(errors, stream)
{
  // stream errors are distinguishable from connection errors
  EXPECT_NE(make_error_condition(error::connection_aborted),
            make_error_code(error::stream_aborted));
  // stream errors can be compared to generic error conditions
  EXPECT_EQ(make_error_condition(errc::connection_reset),
            make_error_code(error::stream_reset));
  EXPECT_EQ(make_error_condition(errc::connection_aborted),
            make_error_code(error::stream_aborted));
  EXPECT_EQ(make_error_condition(errc::device_or_resource_busy),
            make_error_code(error::stream_busy));
}

} // namespace nexus::quic
