# Storage library
add_library(storage
    engine.cpp
    schema.cpp
)

target_include_directories(storage PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(storage
    PUBLIC
        crypto
        SQLite::SQLite3
        Threads::Threads
)

# Unit tests
add_executable(storage_tests
    engine_test.cpp
    schema_test.cpp
)

target_link_libraries(storage_tests
    PRIVATE
        storage
        GTest::GTest
        GTest::Main
)

add_test(NAME storage_tests COMMAND storage_tests)
