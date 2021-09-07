#pragma once

#include <boost/system/error_code.hpp>
#include <boost/asio/error.hpp>

namespace nexus {

namespace errc = boost::system::errc;
using error_code = boost::system::error_code;
using boost::system::system_category;

} // namespace nexus
