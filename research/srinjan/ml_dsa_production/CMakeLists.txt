cmake_minimum_required(VERSION 3.14)
project(ml_dsa_production LANGUAGES CXX)

# ===================================================
# C++ Standard
# ===================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===================================================
# liboqs (change path if different on your machine)
# ===================================================
include_directories(/Users/srinjantambuli/pqc-work/liboqs/build/include)
link_directories(/Users/srinjantambuli/pqc-work/liboqs/build/lib)

# ===================================================
# nlohmann JSON
# (installed via Homebrew: brew install nlohmann-json)
# ===================================================
find_package(nlohmann_json REQUIRED)

# ===================================================
# Include the project headers
# ===================================================
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)

# ===================================================
# Build utility library (base64 + json wrappers)
# ===================================================
add_library(mldsa_utils
    utils/base64.cpp
    utils/ml_dsa_json.cpp
)

target_link_libraries(mldsa_utils
    nlohmann_json::nlohmann_json
)

# ===================================================
# Build core MLDSA library
# ===================================================
add_library(ml_dsa
    src/ml_dsa.cpp
)

target_link_libraries(ml_dsa
    oqs
    mldsa_utils
)

# ===================================================
# Demo executable
# ===================================================
add_executable(ml_dsa_demo
    src/ml_dsa_demo.cpp
)

target_link_libraries(ml_dsa_demo
    ml_dsa
    mldsa_utils
    oqs
    nlohmann_json::nlohmann_json
)
