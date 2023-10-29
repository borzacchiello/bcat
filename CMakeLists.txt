cmake_minimum_required(VERSION 3.19)

project(bcat C)

option(ASAN "Compile with asan (only for debug builds)" OFF)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNO_LOGGING=1 -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall -Wextra")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

add_subdirectory(btran)

add_executable(bcat
    bcat.c)
target_link_libraries(bcat LINK_PUBLIC libbtran_static)
