cmake_minimum_required(VERSION 4.1)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g -O1 -fno-omit-frame-pointer")
project(first_c_project C)
enable_testing()
set(CMAKE_C_STANDARD 23)
find_package(unofficial-sodium CONFIG REQUIRED)
add_library(core_logic
        src/encryption.c
        src/database.c
        libraries/sqlite3.c
        include/sqlite3.h
        libraries/sqlite3.c
)
target_include_directories(core_logic PUBLIC include)
target_link_libraries(core_logic PUBLIC unofficial-sodium::sodium)

add_executable(first_c_project src/main.c)
target_link_libraries(first_c_project PRIVATE core_logic)

add_executable(first_c_project_test_database tests/test_database.c
        tests/unity/unity.c
        tests/unity/unity_internals.h
        tests/unity/unity.h)
target_link_libraries(first_c_project_test_database PRIVATE core_logic)

add_executable(first_c_project_test_encryption tests/test_encryption.c
        tests/unity/unity.c
        tests/unity/unity_internals.h
        tests/unity/unity.h)
target_link_libraries(first_c_project_test_encryption PRIVATE core_logic)

add_test(NAME DatabaseTest COMMAND first_c_project_test_database)
add_test(NAME EncryptionTest COMMAND first_c_project_test_encryption)