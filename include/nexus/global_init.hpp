#pragma once

#include <nexus/global/context.hpp>

namespace nexus::global {

/// initialize the library for clients only
context init_client(error_code& ec);
/// initialize the library for clients only
context init_client();

/// initialize the library for server only
context init_server(error_code& ec);
/// initialize the library for server only
context init_server();

/// initialize the library for client and server use
context init_client_server(error_code& ec);
/// initialize the library for client and server use
context init_client_server();

} // namespace nexus::global
