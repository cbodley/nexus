add_subdirectory(dependency)

add_library(test_base INTERFACE)
target_link_libraries(test_base INTERFACE gtest_main)
target_include_directories(test_base INTERFACE include)

# all warnings as errors
if(MSVC)
       target_compile_options(test_base INTERFACE /W4 /WX)
else(MSVC)
       target_compile_options(test_base INTERFACE -Wall -Wextra -Werror)
endif(MSVC)

if(NEXUS_TEST_ADDRESS_SANITIZER)
       # add address sanitizier
       target_compile_options(test_base INTERFACE "-fsanitize=address")
       target_link_libraries(test_base INTERFACE "-fsanitize=address")
endif()

add_subdirectory(test)
