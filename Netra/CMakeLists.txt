cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()

project(Netra VERSION 0.2.0 LANGUAGES CXX)

# ============================================================================
# Build Options
# ============================================================================
option(NETRA_ENABLE_PCAP "Enable libpcap/Npcap capture support when available" ON)
option(NETRA_ENABLE_TESTS "Enable unit tests" ON)
option(NETRA_ENABLE_DOCS "Enable Doxygen documentation" OFF)
option(NETRA_ENABLE_PROFILING "Enable performance profiling" OFF)
option(NETRA_ENABLE_LOGGING "Enable file logging" ON)
option(NETRA_BUILD_SHARED "Build as shared library" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NETRA_ENABLE_PCAP)
    find_package(Pcap QUIET)
endif()

# ============================================================================
# Core Library
# ============================================================================
set(NETRA_CORE_SOURCES
    src/analyzer/ArtifactHunter.cpp
    src/analyzer/TrafficAnalyzer.cpp
    src/config/AppConfig.cpp
    src/core/Application.cpp
    src/core/DashboardState.cpp
    src/i18n/Localizer.cpp
    src/core/PcapCaptureSource.cpp
    src/filter/DisplayFilter.cpp
    src/parser/PacketParser.cpp
    src/plugin/PluginManager.cpp
    src/ui/Renderer.cpp
    src/ui/Terminal.cpp
    src/logging/Logger.cpp
    src/error/Exceptions.cpp
    src/profiling/Metrics.cpp
)

if(NETRA_BUILD_SHARED)
    set(LIBRARY_TYPE "SHARED")
    add_library(netra_core SHARED ${NETRA_CORE_SOURCES})
else()
    set(LIBRARY_TYPE "STATIC")
    add_library(netra_core STATIC ${NETRA_CORE_SOURCES})
endif()

add_library(Netra::core ALIAS netra_core)

target_include_directories(netra_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(Pcap_FOUND)
    target_compile_definitions(netra_core PUBLIC NETRA_HAS_PCAP=1)
else()
    target_compile_definitions(netra_core PUBLIC NETRA_HAS_PCAP=0)
    message(STATUS "Pcap/Npcap not found: building Netra without live capture backend")
endif()

if(NETRA_ENABLE_LOGGING)
    target_compile_definitions(netra_core PUBLIC NETRA_LOGGING_ENABLED=1)
else()
    target_compile_definitions(netra_core PUBLIC NETRA_LOGGING_ENABLED=0)
endif()

if(NETRA_ENABLE_PROFILING)
    target_compile_definitions(netra_core PUBLIC NETRA_PROFILING_ENABLED=1)
else()
    target_compile_definitions(netra_core PUBLIC NETRA_PROFILING_ENABLED=0)
endif()

# Platform-specific definitions
if(WIN32)
    target_compile_definitions(netra_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN NETRA_WINDOWS)
elseif(APPLE)
    target_compile_definitions(netra_core PUBLIC NETRA_MACOS)
elseif(UNIX)
    target_compile_definitions(netra_core PUBLIC NETRA_LINUX)
endif()

# ============================================================================
# Compiler Options
# ============================================================================
if(MSVC)
    target_compile_options(netra_core PRIVATE
        /W4              # Warning level 4
        /permissive-     # Standards conformance
        /EHsc            # Exception handling
        /utf-8           # UTF-8 source files
        /fp:precise      # Floating point precision
    )
    # Use DLL runtime for compatibility with Google Test
    set_target_properties(netra_core PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
else()
    target_compile_options(netra_core PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
        -Wnon-virtual-dtor -Wold-style-cast -Woverloaded-virtual
    )
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        target_compile_options(netra_core PRIVATE -Wduplicated-branches -Wduplicated-cond)
    endif()
endif()

# ============================================================================
# Dependencies
# ============================================================================
find_package(Threads REQUIRED)
target_link_libraries(netra_core PRIVATE Threads::Threads)

if(Pcap_FOUND)
    target_link_libraries(netra_core PRIVATE Pcap::Pcap)
endif()

if(WIN32)
    target_link_libraries(netra_core PRIVATE ws2_32 iphlpapi)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(netra_core PRIVATE dl)
endif()

# ============================================================================
# Executable
# ============================================================================
add_executable(netra src/main.cpp)
target_link_libraries(netra PRIVATE netra_core)

if(MSVC)
    set_target_properties(netra PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

# ============================================================================
# Installation
# ============================================================================
install(TARGETS netra RUNTIME DESTINATION bin)
install(DIRECTORY include/netra DESTINATION include)
install(FILES config/netra.example.ini DESTINATION share/netra)

# ============================================================================
# Testing
# ============================================================================
if(NETRA_ENABLE_TESTS)
    message(STATUS "Tests enabled")
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================================================
# Documentation
# ============================================================================
if(NETRA_ENABLE_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        message(STATUS "Doxygen found: documentation will be generated")
        add_subdirectory(docs)
    else()
        message(WARNING "Doxygen not found: documentation will not be generated")
    endif()
endif()

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "Netra Configuration Summary:")
message(STATUS "  Version:              ${PROJECT_VERSION}")
message(STATUS "  C++ Standard:         ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "  Library Type:         ${LIBRARY_TYPE}")
message(STATUS "  Pcap Support:         ${NETRA_ENABLE_PCAP} (Found: ${Pcap_FOUND})")
message(STATUS "  Tests:                ${NETRA_ENABLE_TESTS}")
message(STATUS "  Documentation:        ${NETRA_ENABLE_DOCS}")
message(STATUS "  File Logging:         ${NETRA_ENABLE_LOGGING}")
message(STATUS "  Performance Metrics:  ${NETRA_ENABLE_PROFILING}")
message(STATUS "")
