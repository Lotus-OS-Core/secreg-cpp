# Daemon executable
add_executable(secregd
    main.cpp
    daemon.cpp
    server.cpp
    auth.cpp
    acl.cpp
    audit.cpp
)

target_include_directories(secregd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(secregd
    PRIVATE
        storage
        daemon_lib
        Threads::Threads
)

target_link_libraries(secregd PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Daemon internal library
add_library(daemon_lib
    daemon.cpp
    server.cpp
    auth.cpp
    acl.cpp
    audit.cpp
)

target_include_directories(daemon_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(daemon_lib PRIVATE storage crypto)

# Unit tests
add_executable(daemon_tests
    daemon_test.cpp
    server_test.cpp
    auth_test.cpp
    acl_test.cpp
    audit_test.cpp
)

target_link_libraries(daemon_tests
    PRIVATE
        daemon_lib
        storage
        crypto
        GTest::GTest
        GTest::Main
)

add_test(NAME daemon_tests COMMAND daemon_tests)
