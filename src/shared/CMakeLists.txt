# Shared library
add_library(shared
    types.cpp
    errors.cpp
    constants.cpp
    utils.cpp
)

target_include_directories(shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(shared
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
)
