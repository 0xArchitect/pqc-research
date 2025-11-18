cmake_minimum_required(VERSION 3.10)
project(pqc_with_oqs)

set(CMAKE_CXX_STANDARD 17)

# 1. Add include directory for OQS headers
include_directories(/Users/srinjantambuli/pqc-work/liboqs/build/include)

# 2. Add library directory for liboqs.a
link_directories(/Users/srinjantambuli/pqc-work/liboqs/build/lib)

# Your executables
add_executable(pqc_test pqc_test.cpp)
add_executable(lwe_demo lwe_demo.cpp)

# 3. Link liboqs to pqc_test only (lwe_demo doesn’t need it)
target_link_libraries(pqc_test oqs)
