cmake_minimum_required (VERSION 3.5.1)
project(nexus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.66 REQUIRED COMPONENTS system)

add_library(nexus INTERFACE)
target_include_directories(nexus INTERFACE include)
target_link_libraries(nexus INTERFACE Boost::system)
install(DIRECTORY include/nexus DESTINATION include)

set(NEXUS_TEST_SANITIZERS "address" CACHE STRING "build nexus tests with sanitizers")

option(NEXUS_BUILD_TESTS "build nexus tests" ON)
if(NEXUS_BUILD_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()
