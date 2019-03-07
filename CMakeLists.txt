cmake_minimum_required (VERSION 3.5.1)
project(http2)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.66 REQUIRED COMPONENTS system)

add_library(http2 INTERFACE)
target_include_directories(http2 INTERFACE include)
target_link_libraries(http2 INTERFACE Boost::system)

option(HTTP2_TEST_ADDRESS_SANITIZER "build http2 tests with address sanitizer" ON)

enable_testing()
add_subdirectory(test EXCLUDE_FROM_ALL)
