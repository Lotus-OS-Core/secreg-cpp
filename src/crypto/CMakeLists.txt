# Crypto library
add_library(crypto
    crypto_manager.cpp
    encrypt.cpp
    keyring.cpp
)

target_include_directories(crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(crypto
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(TPM2_FOUND)
    target_compile_definitions(crypto PUBLIC SECREG_TPM_ENABLED=1)
    target_link_libraries(crypto PUBLIC tss2)
endif()

# Unit tests
add_executable(crypto_tests
    crypto_manager_test.cpp
    encrypt_test.cpp
    keyring_test.cpp
)

target_link_libraries(crypto_tests
    PRIVATE
        crypto
        GTest::GTest
        GTest::Main
)

add_test(NAME crypto_tests COMMAND crypto_tests)
