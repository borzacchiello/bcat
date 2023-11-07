cmake_minimum_required(VERSION 3.19)

project(btran C)

option(ASAN "Compile with asan (only for debug builds)" OFF)

set(CMAKE_C_STANDARD 99)

set(src
    
    btran.c
    icmp.c
    tcp.c
    udp.c
    ikcp.c
    ll.c
    salsa20.c
    sha256.c
    alloc.c
    log.c)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -DNO_LOGGING=1 -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall -Wextra")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

add_library(libbtran OBJECT ${src})

set_property(TARGET libbtran PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(libbtran_static STATIC $<TARGET_OBJECTS:libbtran>)
add_library(libbtran_shared SHARED $<TARGET_OBJECTS:libbtran>)

set_target_properties(libbtran_static PROPERTIES OUTPUT_NAME btran)
set_target_properties(libbtran_shared PROPERTIES OUTPUT_NAME btran)

install(FILES btran.h DESTINATION include)
