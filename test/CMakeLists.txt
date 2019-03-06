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
