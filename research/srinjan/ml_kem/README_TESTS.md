# How to Build and Run ML-KEM Unit Tests

## Prerequisites
- liboqs library installed
- OpenSSL installed
- A C++ compiler (g++, clang, or MSVC)

## Option 1: Using CMake (Recommended)

### Install CMake
Download and install CMake from: https://cmake.org/download/

Add CMake to your system PATH, then:

```bash
cd b:\PQC\pqc-research\research\srinjan\ml_kem
cmake -B build
cmake --build build
.\build\Debug\test_ml_kem.exe
```

## Option 2: Using Visual Studio

If you have Visual Studio installed:

1. Open **Developer Command Prompt for Visual Studio**
2. Navigate to the ml_kem directory
3. Run the CMake commands above

## Option 3: Using MSYS2/MinGW (g++)

If you have MSYS2 or MinGW installed:

```bash
cd b:\PQC\pqc-research\research\srinjan\ml_kem

# Update the paths below to match your liboqs installation
g++ -std=c++17 -o test_ml_kem.exe \
    test_ml_kem.cpp ml_kem.cpp \
    -I<path_to_liboqs>/include \
    -L<path_to_liboqs>/lib \
    -loqs -lssl -lcrypto

.\test_ml_kem.exe
```

## Option 4: Using the Same Method You Used for demo_ml_kem

Since you already compiled `demo_ml_kem.cpp` before, use the same method for `test_ml_kem.cpp`.

**If you used CMake before:**
Just run `cmake --build build` again and it will compile the new test file.

**If you used a manual command:**
Replace `demo_ml_kem.cpp` with `test_ml_kem.cpp` in your compile command.

## Expected Test Output

When you run `test_ml_kem.exe`, you should see:

```
╔════════════════════════════════════════════════════════════════╗
║           ML-KEM UNIT TEST SUITE                               ║
╚════════════════════════════════════════════════════════════════╝

▶ Running: test_basic_kem_workflow...
  Public Key (16 bytes): 8a3f2b...
  Secret Key (16 bytes): 1c9e4d...
  ... (detailed output)
✔ PASSED: test_basic_kem_workflow

▶ Running: test_encryption_decryption...
  Original Message: "Hello, Post-Quantum World! This is a secret message."
  ... (encryption details)
  Decrypted Message: "Hello, Post-Quantum World! This is a secret message."
✔ PASSED: test_encryption_decryption

... (4 more tests)

╔════════════════════════════════════════════════════════════════╗
║  TEST SUMMARY                                                  ║
╚════════════════════════════════════════════════════════════════╝
  Total Tests: 6
  ✔ Passed: 6
  ✘ Failed: 0

🎉 ALL TESTS PASSED! 🎉
```

## Need Help?

**Question**: How did you compile `demo_ml_kem.cpp` previously?

Use the same method for `test_ml_kem.cpp` and it should work!
