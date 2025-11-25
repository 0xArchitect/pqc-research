cmake_minimum_required(VERSION 3.10)
project(pqc_with_oqs)

set(CMAKE_CXX_STANDARD 17)

# OQS only needed for pqc_test
include_directories(/Users/srinjantambuli/pqc-work/liboqs/build/include)
link_directories(/Users/srinjantambuli/pqc-work/liboqs/build/lib)

# ---- Targets ----

# liboqs example
add_executable(pqc_test pqc_test.cpp)
target_link_libraries(pqc_test oqs)

# LWE (no external libs)
add_executable(lwe_demo lwe_demo.cpp)

# LWR (no external libs)
add_executable(lwr_demo lwr_demo.cpp)
