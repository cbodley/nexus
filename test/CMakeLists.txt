find_package(GTest REQUIRED)

add_library(test_base certificate.cc)
target_include_directories(test_base PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_base PUBLIC nexus GTest::gtest GTest::gtest_main)

function(add_unit_test target)
	add_executable(${target} ${ARGN})
	target_link_libraries(${target} address-sanitizer)
	add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
endfunction()

add_subdirectory(headers)

add_subdirectory(h3)
add_subdirectory(quic)
