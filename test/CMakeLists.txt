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

add_executable(test_protocol test_protocol.cc)
target_link_libraries(test_protocol http2 test_base)
#add_test(test_protocol test_protocol) # just test compile

add_executable(test_hpack_integer test_hpack_integer.cc)
target_link_libraries(test_hpack_integer http2 test_base)
add_test(test_hpack_integer test_hpack_integer)

add_executable(test_hpack_string test_hpack_string.cc)
target_link_libraries(test_hpack_string http2 test_base)
add_test(test_hpack_string test_hpack_string)

add_executable(test_hpack_dynamic_table test_hpack_dynamic_table.cc)
target_link_libraries(test_hpack_dynamic_table http2 test_base)
add_test(test_hpack_dynamic_table test_hpack_dynamic_table)

add_executable(test_hpack_header test_hpack_header.cc)
target_link_libraries(test_hpack_header http2 test_base)
add_test(test_hpack_header test_hpack_header)

find_package(OpenSSL 1.0.2 REQUIRED)

add_executable(test_ssl_alpn test_ssl_alpn.cc)
target_link_libraries(test_ssl_alpn http2 test_base OpenSSL::SSL OpenSSL::Crypto)
add_test(test_ssl_alpn test_ssl_alpn)
