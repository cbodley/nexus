cmake_minimum_required (VERSION 3.5.1)
project(nexus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(nexus INTERFACE)
target_include_directories(nexus INTERFACE include)

option(NEXUS_TEST_ADDRESS_SANITIZER "build nexus tests with address sanitizer" ON)

option(NEXUS_BUILD_TESTS "build nexus tests" ON)
if(NEXUS_BUILD_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
