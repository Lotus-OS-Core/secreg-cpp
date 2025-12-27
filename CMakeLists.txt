cmake_minimum_required(VERSION 3.16)
project(SecReg-Linux VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set module path for custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

# Default build type to Release
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# Check for optional dependencies
pkg_check_modules(TPM2 tss2>=2.4 OPTIONAL_TPM)

# Print configuration summary
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "SQLite3 version: ${SQLITE_VERSION}")
if(TPM2_FOUND)
    message(STATUS "TPM2 support: enabled")
else()
    message(STATUS "TPM2 support: disabled")
endif()

# Subdirectories
add_subdirectory(src/crypto)
add_subdirectory(src/storage)
add_subdirectory(src/daemon)
add_subdirectory(src/cli)
add_subdirectory(src/shared)
add_subdirectory(src/tests)

# Installation configuration
include(GNUInstallDirs)

# Install main binaries
install(TARGETS secregd sreg DESTINATION ${CMAKE_INSTALL_BINDIR})

# Install configuration
install(DIRECTORY assets/ DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/secreg
    FILES_MATCHING PATTERN "*.toml" PATTERN "*.conf")

# Install systemd units
install(FILES assets/registry.service
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)

# Install PAM module
install(TARGETS pam_secreg DESTINATION ${CMAKE_SECURITY_DIR})

# Install documentation
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Install shell completion
install(FILES assets/sreg-completion.bash
    DESTINATION ${CMAKE_INSTALL_DATADIR}/bash-completion/completions)

# Uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake"
    IMMUTABLE TRUE)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P
    "${CMAKE_CURRENT_BINARY_DIR}/Uninstall.cmake")

# Code coverage
option(ENABLE_COVERAGE "Enable code coverage" OFF)
if(ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
endif()

# Static analysis
option(ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXECUTABLE NAMES clang-tidy)
    if(CLANG_TIDY_EXECUTABLE)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXECUTABLE}")
    endif()
endif()

# Sanitizers
option(ENABLE_SANITIZERS "Enable sanitizers" OFF)
if(ENABLE_SANITIZERS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# CPack configuration
set(CPACK_PACKAGE_NAME "secreg")
set(CPACK_PACKAGE_VENDOR "SecReg Security Team")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure Linux Registry System")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl-dev, libsqlite3-dev, libpam0g-dev")
set(CPACK_RPM_PACKAGE_REQUIRES "openssl-devel, sqlite-devel, pam-devel")
include(CPack)
