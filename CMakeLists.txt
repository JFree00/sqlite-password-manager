cmake_minimum_required(VERSION 4.1)
project(first_c_project C)

set(CMAKE_C_STANDARD 23)
find_package(unofficial-sodium CONFIG REQUIRED)
add_executable(first_c_project main.c encryption.h
        encryption.c)
target_link_libraries(first_c_project PRIVATE unofficial-sodium::sodium)