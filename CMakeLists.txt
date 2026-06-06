cmake_minimum_required(VERSION 3.15)
project(CipherApp VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/utf-8)
endif()

add_library(cipher_lib STATIC
    cipher_utils.cpp
    cipher_gamma.cpp
    cipher_affine.cpp
    cipher_affine_recurrent.cpp
    vigenere.cpp
    vernam.cpp
    permutation.cpp
)
target_include_directories(cipher_lib PUBLIC .)

add_library(classical_cipher_lib STATIC
    crypto_utils.cpp
    language_model.cpp
    simple_substitution.cpp
    hill.cpp
    recurrent_hill.cpp
    cipher_classical.cpp
)
target_include_directories(classical_cipher_lib PUBLIC .)

# ── Основной исполняемый файл ─────────────────────────────────────────────────
add_executable(cipher_app main.cpp)
target_link_libraries(cipher_app PRIVATE cipher_lib classical_cipher_lib)

# ── Тесты ─────────────────────────────────────────────────────────────────────
set(HAS_TESTS FALSE)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_cipher.cpp" OR
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_classical.cpp")

    include(FetchContent)
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG        v2.4.12
    )
    FetchContent_MakeAvailable(doctest)
    enable_testing()
    set(HAS_TESTS TRUE)
endif()

if(HAS_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_cipher.cpp")
    add_executable(test_cipher test_cipher.cpp)
    target_include_directories(test_cipher PRIVATE .)
    target_link_libraries(test_cipher PRIVATE cipher_lib doctest::doctest)
    add_test(NAME CipherTests COMMAND test_cipher)
endif()

if(HAS_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_classical.cpp")
    add_executable(test_classical test_classical.cpp)
    target_include_directories(test_classical PRIVATE .)
    target_link_libraries(test_classical PRIVATE
        cipher_lib classical_cipher_lib doctest::doctest)
    add_test(NAME NewCipherTests COMMAND test_classical)
endif()
