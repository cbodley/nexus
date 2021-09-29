# add an executable for each header just to test that it's self-contained
set(NEXUS_HEADER_DIR ${CMAKE_SOURCE_DIR}/include)
file(GLOB_RECURSE HEADER_FILES CONFIGURE_DEPENDS ${NEXUS_HEADER_DIR}/*.hpp)
#list(FILTER HEADER_FILES EXCLUDE REGEX detail)

function(add_header_test target include_path)
	set(HEADER_TEST_FILENAME ${target}.cc)
	add_custom_command(OUTPUT ${HEADER_TEST_FILENAME}
		COMMAND ${CMAKE_COMMAND}
		-DHEADER_TEST_FILENAME=${HEADER_TEST_FILENAME}
		-DHEADER_TEST_INCLUDE_PATH=${include_path}
		-P ${CMAKE_MODULE_PATH}/GenerateHeaderTest.cmake)
	add_executable(${target} ${HEADER_TEST_FILENAME})
	target_link_libraries(${target} PRIVATE nexus gtest_main)
	# do not run this as a unit test
endfunction()

foreach(HEADER ${HEADER_FILES})
	string(REPLACE "${NEXUS_HEADER_DIR}/" "" RELATIVE_HEADER ${HEADER})
	string(REGEX REPLACE "[/\.]" "_" TARGET_NAME "include_${RELATIVE_HEADER}")
	add_header_test(${TARGET_NAME} ${RELATIVE_HEADER})
endforeach()
