cmake_minimum_required(VERSION 3.2...3.16)

project(ShodanCPP)
include_directories("rapidjson/" "curl/include/")

set(CMAKE_CXX_STANDARD 14)

set(LIBRARY_OUTPUT_PATH "lib")
set(LIB_CURL_D_PATH "curl/bin/x64/Cdebug/libcurl.lib")
set(LIB_CURL_R_PATH "curl/bin/x64/Crelease/libcurl.lib")
set(LIB_LIBSSL_PATH "openssl/bin/libssl-vc142-x64-1_1_0.lib")
set(LIB_LIBCRYPTO_PATH "openssl/bin/libcrypto-vc142-x64-1_1_0.lib")

add_library(ShodanCPP shodanCPP/ShodanClient.h shodanCPP/ShodanClient.cpp)
target_link_libraries(ShodanCPP debug ${LIB_CURL_D_PATH})
target_link_libraries(ShodanCPP release ${LIB_CURL_R_PATH})
target_link_libraries(ShodanCPP ${LIB_LIBSSL_PATH})
target_link_libraries(ShodanCPP ${LIB_LIBCRYPTO_PATH})

