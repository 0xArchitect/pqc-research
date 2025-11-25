cmake_minimum_required(VERSION 3.10)
project(ml_dsa_demo)

set(CMAKE_CXX_STANDARD 17)

include_directories(/Users/srinjantambuli/pqc-work/liboqs/build/include)
link_directories(/Users/srinjantambuli/pqc-work/liboqs/build/lib)

add_library(ml_dsa STATIC ml_dsa.cpp)
target_link_libraries(ml_dsa PUBLIC oqs)

add_executable(ml_dsa_demo demo_ml_dsa.cpp)
target_link_libraries(ml_dsa_demo ml_dsa oqs)
