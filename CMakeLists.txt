project(sucky)
cmake_minimum_required(VERSION 3.21)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
add_definitions(-D__USE_GNU)
add_library(sucky SHARED main.c)
target_link_libraries(sucky dl)

