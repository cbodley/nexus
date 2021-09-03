cmake_minimum_required (VERSION 3.5.1)
project(nexus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(dependency)

add_library(nexus INTERFACE)
target_include_directories(nexus INTERFACE include)
target_link_libraries(nexus INTERFACE lsquic)

add_subdirectory(examples)

enable_testing()
add_subdirectory(test EXCLUDE_FROM_ALL)
