# CLI executable
add_executable(sreg
    main.cpp
    cli.cpp
    commands.cpp
)

target_include_directories(sreg PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(sreg
    PRIVATE
        cli_lib
        OpenSSL::SSL
        OpenSSL::Crypto
)

# CLI library
add_library(cli_lib
    cli.cpp
    commands.cpp
)

target_include_directories(cli_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cli_lib PRIVATE shared daemon_lib)

# Unit tests
add_executable(cli_tests
    cli_test.cpp
    commands_test.cpp
)

target_link_libraries(cli_tests
    PRIVATE
        cli_lib
        GTest::GTest
        GTest::Main
)

add_test(NAME cli_tests COMMAND cli_tests)
