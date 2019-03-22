add_subdirectory(dependency)

add_library(test_base INTERFACE)
target_link_libraries(test_base INTERFACE gtest_main)

# all warnings as errors
if(MSVC)
	target_compile_options(test_base INTERFACE /W4 /WX)
else(MSVC)
	target_compile_options(test_base INTERFACE -Wall -Wextra -Werror)
endif(MSVC)

if(HTTP2_TEST_ADDRESS_SANITIZER)
	# add address sanitizier
	target_compile_options(test_base INTERFACE "-fsanitize=address")
	target_link_libraries(test_base INTERFACE "-fsanitize=address")
endif()

add_subdirectory(hpack)

add_executable(test_protocol test_protocol.cc)
target_link_libraries(test_protocol http2 test_base)
#add_test(test_protocol test_protocol) # just test compile

add_executable(test_error test_error.cc)
target_link_libraries(test_error http2 test_base)
#add_test(test_error test_error) # just test compile

add_executable(test_frame test_frame.cc)
target_link_libraries(test_frame http2 test_base)
add_test(test_frame test_frame)

add_executable(test_settings test_settings.cc)
target_link_libraries(test_settings http2 test_base)
add_test(test_settings test_settings)

add_executable(test_basic_connection_settings test_basic_connection_settings.cc)
target_link_libraries(test_basic_connection_settings http2 test_base)
add_test(test_basic_connection_settings test_basic_connection_settings)

add_executable(test_basic_connection_flow_control test_basic_connection_flow_control.cc)
target_link_libraries(test_basic_connection_flow_control http2 test_base)
add_test(test_basic_connection_flow_control test_basic_connection_flow_control)

add_executable(test_basic_connection_headers test_basic_connection_headers.cc)
target_link_libraries(test_basic_connection_headers http2 test_base)
add_test(test_basic_connection_headers test_basic_connection_headers)

add_executable(test_basic_connection_data test_basic_connection_data.cc)
target_link_libraries(test_basic_connection_data http2 test_base)
add_test(test_basic_connection_data test_basic_connection_data)

add_executable(test_basic_connection_priority test_basic_connection_priority.cc)
target_link_libraries(test_basic_connection_priority http2 test_base)
add_test(test_basic_connection_priority test_basic_connection_priority)

add_executable(test_basic_connection_ping test_basic_connection_ping.cc)
target_link_libraries(test_basic_connection_ping http2 test_base)
add_test(test_basic_connection_ping test_basic_connection_ping)

find_package(OpenSSL 1.0.2 REQUIRED)

add_executable(test_ssl_alpn test_ssl_alpn.cc)
target_link_libraries(test_ssl_alpn http2 test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_ssl_alpn test_ssl_alpn)

add_executable(test_client_connection test_client_connection.cc)
target_link_libraries(test_client_connection http2 test_base)
add_test(test_client_connection test_client_connection)

add_executable(test_ssl_client_connection test_ssl_client_connection.cc)
target_link_libraries(test_ssl_client_connection http2 test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_ssl_client_connection test_ssl_client_connection)

add_executable(test_server_connection test_server_connection.cc)
target_link_libraries(test_server_connection http2 test_base)
add_test(test_server_connection test_server_connection)
