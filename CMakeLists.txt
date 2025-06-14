cmake_minimum_required(VERSION 3.20)
project(file-crypt LANGUAGES CXX)

# C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Универсальные warning-флаги
if(MSVC)
    # для MSVC
    add_compile_options(/W4 /permissive-)
else()
    # для GCC/Clang
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# OpenSSL (может быть из vcpkg toolchain или из системной установки)
find_package(OpenSSL REQUIRED)

# doctest: сначала ищем установленный, иначе подтягиваем через FetchContent
find_package(doctest CONFIG QUIET)

if(NOT doctest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        doctest
        URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.11.tar.gz
        URL_HASH SHA256=24e70b9ce0d6b6f6a3e0f33e27e3c2c164b2f6c4165ea72f28a3d8a9e6161b97
    )
    FetchContent_MakeAvailable(doctest)
endif()

# Библиотека filecrypt
add_library(filecrypt STATIC
    crypto.cpp
)

target_include_directories(filecrypt
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(filecrypt
    PUBLIC OpenSSL::Crypto OpenSSL::SSL
)

# CLI-утилита
add_executable(filecrypt_cli
    main.cpp
)

target_link_libraries(filecrypt_cli
    PRIVATE filecrypt
)

# Юнит-тесты
enable_testing()
add_executable(filecrypt_tests
    tests.cpp
)

target_link_libraries(filecrypt_tests
    PRIVATE filecrypt doctest::doctest
)

add_test(NAME all COMMAND filecrypt_tests)