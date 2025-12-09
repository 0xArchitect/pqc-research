# How to Build and Run ML-DSA Unit Tests

## Prerequisites
- liboqs library installed
- Google Test library installed
- A C++ compiler (g++, clang, or MSVC)

## Option 1: Using CMake (Recommended)

### Install CMake
Download and install CMake from: https://cmake.org/download/

Add CMake to your system PATH, then:

```bash
cd b:\PQC\pqc-research\research\srinjan\ml_dsa
cmake -B build
cmake --build build
.\build\Debug\ml_dsa_test.exe
```

**Or use the convenient batch script:**
```bash
.\run_tests.bat
```

## Option 2: Using Visual Studio

If you have Visual Studio installed:

1. Open **Developer Command Prompt for Visual Studio**
2. Navigate to the ml_dsa directory
3. Run the CMake commands above

## Option 3: Using MSYS2/MinGW (g++)

If you have MSYS2 or MinGW installed:

```bash
cd b:\PQC\pqc-research\research\srinjan\ml_dsa

# Update the paths below to match your liboqs and Google Test installation
g++ -std=c++17 -o ml_dsa_test.exe \
    test_ml_dsa.cpp ml_dsa.cpp \
    -I<path_to_liboqs>/include \
    -I<path_to_gtest>/include \
    -L<path_to_liboqs>/lib \
    -L<path_to_gtest>/lib \
    -loqs -lgtest -lgtest_main -pthread

.\ml_dsa_test.exe
```

## Option 4: Using the Same Method You Used for demo_ml_dsa

Since you already compiled `demo_ml_dsa.cpp` before, use the same method for `test_ml_dsa.cpp`.

**If you used CMake before:**
Just run `cmake --build build` again and it will compile the new test file.

**If you used a manual command:**
Replace `demo_ml_dsa.cpp` with `test_ml_dsa.cpp` in your compile command, and add Google Test libraries.

## Expected Test Output

When you run `ml_dsa_test.exe`, you should see:

```
[==========] Running 27 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 27 tests from MlDsaTest
[ RUN      ] MlDsaTest.KeypairGeneration_MLDSA44
[       OK ] MlDsaTest.KeypairGeneration_MLDSA44 (15 ms)
[ RUN      ] MlDsaTest.KeypairGeneration_MLDSA65
[       OK ] MlDsaTest.KeypairGeneration_MLDSA65 (18 ms)
[ RUN      ] MlDsaTest.KeypairGeneration_MLDSA87
[       OK ] MlDsaTest.KeypairGeneration_MLDSA87 (22 ms)
[ RUN      ] MlDsaTest.SignAndVerify_BasicMessage
[       OK ] MlDsaTest.SignAndVerify_BasicMessage (12 ms)
[ RUN      ] MlDsaTest.FullWorkflow_AllVariants
[       OK ] MlDsaTest.FullWorkflow_AllVariants (45 ms)
[ RUN      ] MlDsaTest.EmptyMessage
[       OK ] MlDsaTest.EmptyMessage (8 ms)
[ RUN      ] MlDsaTest.SingleByteMessage
[       OK ] MlDsaTest.SingleByteMessage (9 ms)
[ RUN      ] MlDsaTest.LargeMessage_1KB
[       OK ] MlDsaTest.LargeMessage_1KB (11 ms)
[ RUN      ] MlDsaTest.LargeMessage_10KB
[       OK ] MlDsaTest.LargeMessage_10KB (15 ms)
[ RUN      ] MlDsaTest.LargeMessage_1MB
[       OK ] MlDsaTest.LargeMessage_1MB (120 ms)
[ RUN      ] MlDsaTest.InvalidAlgorithmName
[       OK ] MlDsaTest.InvalidAlgorithmName (2 ms)
[ RUN      ] MlDsaTest.EmptyAlgorithmName
[       OK ] MlDsaTest.EmptyAlgorithmName (1 ms)
[ RUN      ] MlDsaTest.TamperedMessage_BitFlip
[       OK ] MlDsaTest.TamperedMessage_BitFlip (10 ms)
[ RUN      ] MlDsaTest.TamperedMessage_ByteChange
[       OK ] MlDsaTest.TamperedMessage_ByteChange (10 ms)
[ RUN      ] MlDsaTest.TamperedSignature_BitFlip
[       OK ] MlDsaTest.TamperedSignature_BitFlip (11 ms)
[ RUN      ] MlDsaTest.TamperedSignature_TruncatedSignature
[       OK ] MlDsaTest.TamperedSignature_TruncatedSignature (9 ms)
[ RUN      ] MlDsaTest.WrongPublicKey
[       OK ] MlDsaTest.WrongPublicKey (20 ms)
[ RUN      ] MlDsaTest.WrongSecretKey_DifferentKeypair
[       OK ] MlDsaTest.WrongSecretKey_DifferentKeypair (19 ms)
[ RUN      ] MlDsaTest.CrossAlgorithm_44_to_65
[       OK ] MlDsaTest.CrossAlgorithm_44_to_65 (25 ms)
[ RUN      ] MlDsaTest.CrossAlgorithm_65_to_87
[       OK ] MlDsaTest.CrossAlgorithm_65_to_87 (30 ms)
[ RUN      ] MlDsaTest.SignatureDeterminism_SameMessage
[       OK ] MlDsaTest.SignatureDeterminism_SameMessage (18 ms)
[ RUN      ] MlDsaTest.MultipleSignatures_DifferentMessages
[       OK ] MlDsaTest.MultipleSignatures_DifferentMessages (95 ms)
[ RUN      ] MlDsaTest.MultipleInstances_Concurrent
[       OK ] MlDsaTest.MultipleInstances_Concurrent (55 ms)
[ RUN      ] MlDsaTest.MultipleInstances_SameAlgorithm
[       OK ] MlDsaTest.MultipleInstances_SameAlgorithm (22 ms)
[----------] 27 tests from MlDsaTest (562 ms total)

[----------] Global test environment tear-down
[==========] 27 tests from 1 test suite ran. (565 ms total)
[  PASSED  ] 27 tests.
```

## Running Specific Tests

### Run only tampering tests:
```bash
.\ml_dsa_test.exe --gtest_filter=*Tampered*
```

### Run only ML-DSA-44 tests:
```bash
.\ml_dsa_test.exe --gtest_filter=*MLDSA44*
```

### Run tests with colored output:
```bash
.\ml_dsa_test.exe --gtest_color=yes
```

### List all available tests:
```bash
.\ml_dsa_test.exe --gtest_list_tests
```

## Running Performance Benchmarks

Performance benchmarks are disabled by default to keep regular test runs fast. To run them:

```bash
.\ml_dsa_test.exe --gtest_also_run_disabled_tests --gtest_filter=*Benchmark*
```

You'll see output like:
```
Keypair generation (100 iterations): 1523 ms
Average per keypair: 15.23 ms

Signing (100 iterations): 1845 ms
Average per signature: 18.45 ms

Verification (100 iterations): 1234 ms
Average per verification: 12.34 ms
```

## Troubleshooting

### Google Test Not Found

If CMake reports that Google Test is not found:

**Option 1: Install via package manager (Linux/MSYS2)**
```bash
# Ubuntu/Debian
sudo apt-get install libgtest-dev

# MSYS2
pacman -S mingw-w64-x86_64-gtest
```

**Option 2: Specify Google Test path manually**
```bash
cmake -B build -DGTEST_ROOT=<path_to_gtest>
```

**Option 3: Download and build Google Test**
```bash
git clone https://github.com/google/googletest.git
cd googletest
cmake -B build
cmake --build build
cmake --install build
```

### pthread Linking Error (Windows)

If you get a pthread linking error on Windows, edit `CMakeLists.txt` and remove `pthread`:

Change:
```cmake
target_link_libraries(ml_dsa_test ml_dsa oqs ${GTEST_LIBRARIES} pthread)
```

To:
```cmake
target_link_libraries(ml_dsa_test ml_dsa oqs ${GTEST_LIBRARIES})
```

### Algorithm Not Enabled

If you see "Signature algorithm not enabled: ML-DSA-XX", make sure your liboqs build includes ML-DSA support.

Check available algorithms:
```bash
# In liboqs build directory
./tests/example_sig | grep ML-DSA
```

### liboqs Path Issues

Update the paths in `CMakeLists.txt` (lines 6-7) to match your liboqs installation:
```cmake
include_directories(/path/to/your/liboqs/build/include)
link_directories(/path/to/your/liboqs/build/lib)
```

## Test Categories

The test suite includes:

✅ **Basic Functionality** - Keypair generation, signing, verification  
✅ **Message Variations** - Empty, small, large messages (up to 1MB)  
✅ **Error Handling** - Invalid algorithm names, exception handling  
✅ **Security Tests** - Tampering detection, wrong keys  
✅ **Cross-Validation** - Algorithm incompatibility checks  
✅ **Performance Benchmarks** - Timing measurements for all operations  
