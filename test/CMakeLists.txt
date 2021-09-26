add_subdirectory(dependency)

add_library(test_base INTERFACE)
target_link_libraries(test_base INTERFACE gtest gtest_main)

function(add_unit_test target)
	add_executable(${target} ${ARGN})
	target_link_libraries(${target} address-sanitizer)
	add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
endfunction()

add_subdirectory(h3)
add_subdirectory(quic)

