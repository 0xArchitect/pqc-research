cmake_minimum_required(VERSION 3.16)
project(ml_dsa_production LANGUAGES CXX)

# ======================
#   C++ Standard
# ======================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ======================
#   Include Paths
# ======================
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    /Users/srinjantambuli/pqc-work/liboqs/build/include
)

link_directories(
    /Users/srinjantambuli/pqc-work/liboqs/build/lib
)

# ======================
#   nlohmann/json
# ======================
find_package(nlohmann_json REQUIRED)

# ======================
#   Utils Library
# ======================
add_library(mldsa_utils
    utils/base64.cpp
    utils/ml_dsa_json.cpp
)

target_link_libraries(mldsa_utils
    nlohmann_json::nlohmann_json
)

# ======================
#   Core MLDSA Library
# ======================
add_library(ml_dsa
    src/ml_dsa.cpp
)

target_link_libraries(ml_dsa
    oqs
    mldsa_utils
    nlohmann_json::nlohmann_json
)

# ======================
#   DEMO: Verbose
# ======================
add_executable(ml_dsa_demo_verbose
    src/demo_verbose.cpp
)

target_link_libraries(ml_dsa_demo_verbose
    ml_dsa
    mldsa_utils
    oqs
    nlohmann_json::nlohmann_json
)

# ======================
#   DEMO: Secure
# ======================
add_executable(ml_dsa_demo_secure
    src/demo_secure.cpp
)

target_link_libraries(ml_dsa_demo_secure
    ml_dsa
    mldsa_utils
    oqs
    nlohmann_json::nlohmann_json
)
