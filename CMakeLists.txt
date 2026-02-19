cmake_minimum_required(VERSION 4.1)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -g -O1 -fno-omit-frame-pointer")
endif ()
project(first_c_project C)
enable_testing()
set(CMAKE_C_STANDARD 23)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
add_library(core_logic
        src/encryption.c
        src/database.c
)
target_include_directories(core_logic PUBLIC include)
target_link_libraries(core_logic PUBLIC unofficial-sodium::sodium)
target_link_libraries(core_logic PUBLIC unofficial::sqlite3::sqlite3)

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

install(TARGETS first_c_project
        RUNTIME DESTINATION bin)

if (WIN32)
    set(X_VCPKG_APPLOCAL_DEPS ON)
endif ()