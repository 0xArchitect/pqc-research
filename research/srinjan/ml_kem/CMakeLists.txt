cmake_minimum_required(VERSION 3.10)
project(ml_kem_demo)

set(CMAKE_CXX_STANDARD 17)

# Path to liboqs (your installed location)
set(OQS_INCLUDE_DIR "/Users/srinjantambuli/pqc-work/liboqs/build/include")
set(OQS_LIB_DIR     "/Users/srinjantambuli/pqc-work/liboqs/build/lib")

find_package(OpenSSL REQUIRED)

include_directories(${OQS_INCLUDE_DIR})
link_directories(${OQS_LIB_DIR})

# Build library
add_library(ml_kem STATIC ml_kem.cpp)
target_link_libraries(ml_kem PUBLIC oqs OpenSSL::Crypto)
target_include_directories(ml_kem PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Build demo
add_executable(ml_kem_demo demo_ml_kem.cpp)
target_link_libraries(ml_kem_demo ml_kem oqs OpenSSL::Crypto)
