#pragma once

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#define SYSTEM_ERROR_NAMESPACE boost::system

namespace nexus {

namespace errc = boost::system::errc;
using boost::system::error_code;
using boost::system::error_condition;
using boost::system::error_category;
using boost::system::system_category;
using boost::system::system_error;

} // namespace nexus
