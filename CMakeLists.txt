cmake_minimum_required(VERSION 3.10)
project(salrs C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(test_scheme)

