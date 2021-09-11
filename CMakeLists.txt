cmake_minimum_required (VERSION 3.5.1)
project(nexus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(dependency)

add_library(address-sanitizer INTERFACE)
target_compile_options(address-sanitizer INTERFACE "-fsanitize=address,undefined")
target_link_libraries(address-sanitizer INTERFACE "-fsanitize=address,undefined")

add_library(thread-sanitizer INTERFACE)
target_compile_options(thread-sanitizer INTERFACE "-fsanitize=thread")
target_link_libraries(thread-sanitizer INTERFACE "-fsanitize=thread")

add_library(nexus INTERFACE)
target_include_directories(nexus INTERFACE include)
target_link_libraries(nexus INTERFACE asio uring)
install(DIRECTORY include/nexus DESTINATION include)

add_subdirectory(examples)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)
