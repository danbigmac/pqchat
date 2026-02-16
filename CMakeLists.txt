cmake_minimum_required(VERSION 3.21)
project(pqchat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PQCHAT_BUILD_TESTS "Build tests" ON)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

add_library(pqchat
  src/crypto/secure_buffer.cpp
  src/crypto/hash.cpp
  src/crypto/hkdf.cpp
  src/crypto/aead.cpp
  src/crypto/ed25519.cpp
  src/crypto/mldsa.cpp
  src/crypto/x25519.cpp
  src/crypto/mlkem.cpp
  src/protocol/prekey_bundle.cpp
  src/protocol/messages.cpp
  src/protocol/transport_auth.cpp
  src/protocol/serialization.cpp
  src/server/in_memory_server.cpp
  src/server/sqlite_store.cpp
  src/server/tcp_wire.cpp
  src/server/tcp_server.cpp
  src/client/client.cpp
  src/client/tcp_server_api.cpp
  src/client/tls_pinning.cpp
)

target_include_directories(pqchat
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(pqchat
  PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    Threads::Threads
)

target_compile_options(pqchat PRIVATE -Wall -Wextra -Wpedantic)

add_executable(pqchat_client src/client/client_main.cpp)
target_link_libraries(pqchat_client PRIVATE pqchat)

add_executable(pqchat_client_cli src/client/client_cli_main.cpp)
target_link_libraries(pqchat_client_cli PRIVATE pqchat)

add_executable(pqchat_network_demo src/client/network_demo_main.cpp)
target_link_libraries(pqchat_network_demo PRIVATE pqchat)

add_executable(pqchat_server src/server/server_main.cpp)
target_link_libraries(pqchat_server PRIVATE pqchat)

if(PQCHAT_BUILD_TESTS)
  enable_testing()
  add_executable(pqchat_tests tests/integration_test.cpp)
  target_link_libraries(pqchat_tests PRIVATE pqchat)
  add_test(NAME pqchat_tests COMMAND pqchat_tests)

  add_executable(pqchat_security_protocol_tests tests/security_protocol_test.cpp)
  target_link_libraries(pqchat_security_protocol_tests PRIVATE pqchat)
  add_test(NAME pqchat_security_protocol_tests COMMAND pqchat_security_protocol_tests)

  add_executable(pqchat_sqlite_auth_tests tests/sqlite_auth_test.cpp)
  target_link_libraries(pqchat_sqlite_auth_tests PRIVATE pqchat)
  add_test(NAME pqchat_sqlite_auth_tests COMMAND pqchat_sqlite_auth_tests)

  add_executable(pqchat_serialization_robustness_tests tests/serialization_robustness_test.cpp)
  target_link_libraries(pqchat_serialization_robustness_tests PRIVATE pqchat)
  add_test(NAME pqchat_serialization_robustness_tests COMMAND pqchat_serialization_robustness_tests)

  add_executable(pqchat_design_coverage_tests tests/design_coverage_test.cpp)
  target_link_libraries(pqchat_design_coverage_tests PRIVATE pqchat)
  add_test(NAME pqchat_design_coverage_tests COMMAND pqchat_design_coverage_tests)

  add_executable(pqchat_hardening_fixes_tests tests/hardening_fixes_test.cpp)
  target_link_libraries(pqchat_hardening_fixes_tests PRIVATE pqchat)
  add_test(NAME pqchat_hardening_fixes_tests COMMAND pqchat_hardening_fixes_tests)
endif()
