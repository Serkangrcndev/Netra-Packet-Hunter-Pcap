cmake_minimum_required(VERSION 3.20)

# ============================================================================
# Google Test Framework
# ============================================================================
include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Disable install for gtest
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# ============================================================================
# Unit Tests
# ============================================================================
add_executable(netra_tests
    unit/test_logger.cpp
    unit/test_exceptions.cpp
    unit/test_metrics.cpp
    unit/test_parser_basic.cpp
)

target_link_libraries(netra_tests PRIVATE
    netra_core
    GTest::gtest
    GTest::gtest_main
)

# MSVC runtime library compatibility
if(MSVC)
    set_target_properties(netra_tests PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

target_include_directories(netra_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
)

# ============================================================================
# Register Tests
# ============================================================================
add_test(NAME Netra_Unit_Tests COMMAND netra_tests)

# Enable coverage if supported
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(netra_tests PRIVATE --coverage)
    target_link_options(netra_tests PRIVATE --coverage)
endif()
