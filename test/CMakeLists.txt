add_subdirectory(dependency)

add_library(test_base INTERFACE)
target_link_libraries(test_base INTERFACE gtest_main)
target_include_directories(test_base INTERFACE include)

# all warnings as errors
if(MSVC)
	target_compile_options(test_base INTERFACE /W4 /WX)
else(MSVC)
	target_compile_options(test_base INTERFACE -Wall -Wextra -Werror)
endif(MSVC)

if(NEXUS_TEST_ADDRESS_SANITIZER)
	# add address sanitizier
	target_compile_options(test_base INTERFACE "-fsanitize=address")
	target_link_libraries(test_base INTERFACE "-fsanitize=address")
endif()

add_executable(test_echo_stream test_echo_stream.cc)
target_link_libraries(test_echo_stream nexus test_base)
add_test(test_echo_stream test_echo_stream)

add_subdirectory(hpack)

add_executable(test_base64url test_base64url.cc)
target_link_libraries(test_base64url nexus test_base)
add_test(test_base64url test_base64url)

add_executable(test_stream_buffer test_stream_buffer.cc)
target_link_libraries(test_stream_buffer nexus test_base)
add_test(test_stream_buffer test_stream_buffer)

add_executable(test_protocol test_protocol.cc)
target_link_libraries(test_protocol nexus test_base)
#add_test(test_protocol test_protocol) # just test compile

add_executable(test_error test_error.cc)
target_link_libraries(test_error nexus test_base)
#add_test(test_error test_error) # just test compile

add_executable(test_fields test_fields.cc)
target_link_libraries(test_fields nexus test_base)
add_test(test_fields test_fields)

add_executable(test_frame test_frame.cc)
target_link_libraries(test_frame nexus test_base)
add_test(test_frame test_frame)

add_executable(test_settings test_settings.cc)
target_link_libraries(test_settings nexus test_base)
add_test(test_settings test_settings)

add_executable(test_basic_connection_settings test_basic_connection_settings.cc)
target_link_libraries(test_basic_connection_settings nexus test_base)
add_test(test_basic_connection_settings test_basic_connection_settings)

add_executable(test_basic_connection_flow_control test_basic_connection_flow_control.cc)
target_link_libraries(test_basic_connection_flow_control nexus test_base)
add_test(test_basic_connection_flow_control test_basic_connection_flow_control)

add_executable(test_basic_connection_headers test_basic_connection_headers.cc)
target_link_libraries(test_basic_connection_headers nexus test_base)
add_test(test_basic_connection_headers test_basic_connection_headers)

add_executable(test_basic_connection_data test_basic_connection_data.cc)
target_link_libraries(test_basic_connection_data nexus test_base)
add_test(test_basic_connection_data test_basic_connection_data)

add_executable(test_basic_connection_priority test_basic_connection_priority.cc)
target_link_libraries(test_basic_connection_priority nexus test_base)
add_test(test_basic_connection_priority test_basic_connection_priority)

add_executable(test_basic_connection_ping test_basic_connection_ping.cc)
target_link_libraries(test_basic_connection_ping nexus test_base)
add_test(test_basic_connection_ping test_basic_connection_ping)

add_executable(test_basic_stream test_basic_stream.cc)
target_link_libraries(test_basic_stream nexus test_base)
add_test(test_basic_stream test_basic_stream)

find_package(OpenSSL 1.0.2 REQUIRED)

add_executable(test_ssl_alpn test_ssl_alpn.cc)
target_link_libraries(test_ssl_alpn nexus test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_ssl_alpn test_ssl_alpn)

add_executable(test_client_connection test_client_connection.cc)
target_link_libraries(test_client_connection nexus test_base)
add_test(test_client_connection test_client_connection)

add_executable(test_ssl_client_connection test_ssl_client_connection.cc)
target_link_libraries(test_ssl_client_connection nexus test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_ssl_client_connection test_ssl_client_connection)

add_executable(test_server_connection test_server_connection.cc)
target_link_libraries(test_server_connection nexus test_base)
add_test(test_server_connection test_server_connection)
