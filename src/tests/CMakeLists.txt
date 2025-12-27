# Integration tests
add_executable(integration_tests
    integration_tests.cpp
)

target_link_libraries(integration_tests
    PRIVATE
        storage
        daemon_lib
        crypto
        GTest::GTest
        GTest::Main
)

add_test(NAME integration_tests COMMAND integration_tests)

# Security tests
add_executable(security_tests
    security_tests.cpp
)

target_link_libraries(security_tests
    PRIVATE
        storage
        daemon_lib
        crypto
        GTest::GTest
        GTest::Main
)

add_test(NAME security_tests COMMAND security_tests)

# Audit tests
add_executable(audit_tests
    audit_tests.cpp
)

target_link_libraries(audit_tests
    PRIVATE
        storage
        daemon_lib
        crypto
        GTest::GTest
        GTest::Main
)

add_test(NAME audit_tests COMMAND audit_tests)
