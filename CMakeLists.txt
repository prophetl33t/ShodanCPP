cmake_minimum_required(VERSION 3.2...3.16)

project(ShodanCPP)
include_directories("rapidjson/" "curl/include/")
add_compile_definitions(CURL_STATICLIB USE_SSLEAY USE_OPENSSL)

set(CMAKE_CXX_STANDARD 14)

set(LIBRARY_OUTPUT_PATH "lib")
set(LIB_CURL_D_PATH "${CMAKE_SOURCE_DIR}/curl/bin/x64/Cdebug/libcurl.lib" CACHE FILEPATH "Path to curl static lib for debug build.")
set(LIB_CURL_R_PATH "${CMAKE_SOURCE_DIR}/curl/bin/x64/Crelease/libcurl.lib" CACHE FILEPATH "Path to curl static lib for release build.")
set(LIB_LIBSSL_PATH "${CMAKE_SOURCE_DIR}/openssl/bin/libssl-vc142-x64-1_1_0.lib" CACHE FILEPATH "Path to libssl static lib.")
set(LIB_LIBCRYPTO_PATH "${CMAKE_SOURCE_DIR}/openssl/bin/libcrypto-vc142-x64-1_1_0.lib" CACHE FILEPATH "Path to libcrypto static lib.")


add_library(ShodanCPP ShodanCPP/ShodanClient.h ShodanCPP/ShodanClient.cpp)

IF (WIN32)
target_link_libraries(ShodanCPP "Ws2_32.Lib")
target_link_libraries(ShodanCPP "Crypt32.Lib")
target_link_libraries(ShodanCPP "Wldap32.Lib")
endif()

target_link_libraries(ShodanCPP ${LIB_CURL_R_PATH})
target_link_libraries(ShodanCPP ${LIB_LIBSSL_PATH})
target_link_libraries(ShodanCPP ${LIB_LIBCRYPTO_PATH})

option(BUILD_DEMO "Build demo executable with library usage examples" OFF)

if (BUILD_DEMO)
add_executable(ShodanCPPDemo ShodanCPP/demo.cpp)
target_link_libraries(ShodanCPPDemo PUBLIC ShodanCPP)
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ShodanCPPDemo)
endif()

