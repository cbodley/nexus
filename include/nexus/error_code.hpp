#pragma once

#include <system_error>

#define SYSTEM_ERROR_NAMESPACE std

namespace nexus {

using std::errc;
using std::error_code;
using std::error_condition;
using std::error_category;
using std::system_category;
using std::system_error;

} // namespace nexus
