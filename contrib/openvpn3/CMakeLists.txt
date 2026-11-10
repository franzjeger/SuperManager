cmake_minimum_required(VERSION 3.16)
project(SuperManagerOpenVPN3 LANGUAGES C CXX)
if(NOT APPLE)
    message(FATAL_ERROR "This runtime is built for macOS")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Explicit static archives prevent CMake/pkg-config from selecting Homebrew
# dylibs. The finished executable is checked independently with otool.
foreach(dependency OPENSSL_PREFIX LZ4_PREFIX FMT_PREFIX ASIO_PREFIX CORE_SOURCE)
    if(NOT DEFINED ${dependency})
        message(FATAL_ERROR "Missing ${dependency}")
    endif()
endforeach()
add_library(xkey STATIC
    "${CORE_SOURCE}/openvpn/openssl/xkey/xkey_helper.c"
    "${CORE_SOURCE}/openvpn/openssl/xkey/xkey_provider.c")
target_include_directories(xkey PRIVATE "${OPENSSL_PREFIX}/include")
target_compile_definitions(xkey PRIVATE USE_OPENSSL PUBLIC ENABLE_EXTERNAL_PKI)
add_executable(openvpn3
    "${CORE_SOURCE}/test/ovpncli/cli.cpp"
    "${CORE_SOURCE}/openvpn/crypto/data_epoch.cpp")
target_include_directories(openvpn3 PRIVATE
    "${CORE_SOURCE}" "${OPENSSL_PREFIX}/include" "${LZ4_PREFIX}/include"
    "${FMT_PREFIX}/include" "${ASIO_PREFIX}/include")
target_compile_definitions(openvpn3 PRIVATE
    ASIO_STANDALONE USE_ASIO HAVE_LZ4 USE_OPENSSL)
target_link_libraries(openvpn3 PRIVATE xkey
    "${OPENSSL_PREFIX}/lib/libssl.a" "${OPENSSL_PREFIX}/lib/libcrypto.a"
    "${LZ4_PREFIX}/lib/liblz4.a" "${FMT_PREFIX}/lib/libfmt.a"
    "-framework CoreFoundation" "-framework IOKit"
    "-framework CoreServices" "-framework SystemConfiguration" pthread)
