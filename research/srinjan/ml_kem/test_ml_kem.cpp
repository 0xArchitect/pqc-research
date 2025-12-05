#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cassert>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "ml_kem.hpp"
//
//  This file contains comprehensive unit tests for the ML-KEM implementation.
//  Tests cover:
//      A) Basic KEM workflow (keypair -> encaps -> decaps)
//      B) Different ML-KEM variants (512, 768, 1024)
//      C) Actual encryption/decryption using derived shared secrets
//      D) Error handling and edge cases
//  Run this test suite to verify the implementation works correctly.
// Test result tracking
static int tests_passed = 0;
static int tests_failed = 0;

// Helper macro for test assertions
#define TEST_ASSERT(condition, message) \
    if (!(condition)) { \
        std::cerr << "❌ TEST FAILED: " << message << "\n"; \
        std::cerr << "   at " << __FILE__ << ":" << __LINE__ << "\n"; \
        tests_failed++; \
        return false; \
    }

// Helper macro to run tests
#define RUN_TEST(test_func) \
    do { \
        std::cout << "\n▶ Running: " << #test_func << "...\n"; \
        if (test_func()) { \
            std::cout << "✔ PASSED: " << #test_func << "\n"; \
            tests_passed++; \
        } else { \
            std::cout << "✘ FAILED: " << #test_func << "\n"; \
            tests_failed++; \
        } \
    } while(0)

// ============================================================================
//  HELPER FUNCTIONS
// ============================================================================

// Simple AES-256-GCM encryption using the shared secret as key
// This demonstrates how the ML-KEM shared secret can be used for actual encryption
static bool aes_encrypt(const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &plaintext,
                       std::vector<uint8_t> &ciphertext,
                       std::vector<uint8_t> &iv,
                       std::vector<uint8_t> &tag) {
    
    // Generate random IV (12 bytes for GCM)
    iv.resize(12);
    for (size_t i = 0; i < iv.size(); i++) {
        iv[i] = rand() % 256;
    }
    // Prepare tag storage (16 bytes for GCM)
    tag.resize(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    // Initialize encryption with AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    // Encrypt the plaintext
    ciphertext.resize(plaintext.size() + 16);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ciphertext_len = len;
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    // Get the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
// Simple AES-256-GCM decryption using the shared secret as key
static bool aes_decrypt(const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &ciphertext,
                       const std::vector<uint8_t> &iv,
                       const std::vector<uint8_t> &tag,
                       std::vector<uint8_t> &plaintext) {
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    // Initialize decryption with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    // Decrypt the ciphertext
    plaintext.resize(ciphertext.size() + 16);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int plaintext_len = len;
    
    // Set the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    // Finalize decryption (will fail if tag doesn't match)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
// Print hex for debugging
static void print_hex(const std::vector<uint8_t> &data, const std::string &label) {
    std::cout << "  " << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < std::min(data.size(), size_t(16)); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > 16) std::cout << "...";
    std::cout << std::dec << "\n";
}
// ============================================================================
//  TEST 1: Basic KEM Workflow
// ============================================================================
// Test that the basic ML-KEM-512 key exchange works correctly:
//   1. Generate keypair
//   2. Client encapsulates using public key
//   3. Server decapsulates using secret key
//   4. Both derive the same shared secret
// ============================================================================
static bool test_basic_kem_workflow() {
    try {
        MlKem kem("ML-KEM-512");
        // Step 1: Generate keypair (server side)
        std::vector<uint8_t> pub, sec;
        TEST_ASSERT(kem.keypair(pub, sec), "Keypair generation failed");
        TEST_ASSERT(pub.size() == 800, "Public key size incorrect for ML-KEM-512");
        TEST_ASSERT(sec.size() == 1632, "Secret key size incorrect for ML-KEM-512");
        print_hex(pub, "Public Key");
        print_hex(sec, "Secret Key");
        // Step 2: Encapsulation (client side)
        std::vector<uint8_t> ciphertext, shared_secret_client;
        TEST_ASSERT(kem.encaps(pub, ciphertext, shared_secret_client), "Encapsulation failed");
        TEST_ASSERT(ciphertext.size() == 768, "Ciphertext size incorrect for ML-KEM-512");
        TEST_ASSERT(shared_secret_client.size() == 32, "Shared secret size incorrect");
        print_hex(ciphertext, "Ciphertext");
        print_hex(shared_secret_client, "Shared Secret (Client)");
        // Step 3: Decapsulation (server side)
        std::vector<uint8_t> shared_secret_server;
        TEST_ASSERT(kem.decaps(ciphertext, sec, shared_secret_server), "Decapsulation failed");
        TEST_ASSERT(shared_secret_server.size() == 32, "Shared secret size incorrect");
        
        print_hex(shared_secret_server, "Shared Secret (Server)");
        
        // Step 4: Verify both secrets match
        TEST_ASSERT(shared_secret_client == shared_secret_server, 
                   "Shared secrets do not match!");
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}
// ============================================================================
//  TEST 2: Encryption/Decryption Using Shared Secret
// ============================================================================
// Test that we can use the ML-KEM derived shared secret to actually
// encrypt and decrypt data using AES-256-GCM:
//   1. Perform ML-KEM key exchange
//   2. Client encrypts a message using the shared secret
//   3. Server decrypts the message using the shared secret
//   4. Verify the decrypted message matches the original
// ============================================================================
static bool test_encryption_decryption() {
    try {
        MlKem kem("ML-KEM-512");
        // Perform ML-KEM key exchange
        std::vector<uint8_t> pub, sec;
        kem.keypair(pub, sec);
        std::vector<uint8_t> ciphertext_kem, shared_secret_client;
        kem.encaps(pub, ciphertext_kem, shared_secret_client)
        std::vector<uint8_t> shared_secret_server;
        kem.decaps(ciphertext_kem, sec, shared_secret_server);
        TEST_ASSERT(shared_secret_client == shared_secret_server, 
                   "KEM shared secrets do not match");
        // Now use the shared secret to encrypt actual data
        std::string message = "Hello, Post-Quantum World! This is a secret message.";
        std::vector<uint8_t> plaintext(message.begin(), message.end());
        std::cout << "  Original Message: \"" << message << "\"\n";
        // Client encrypts using the shared secret
        std::vector<uint8_t> ciphertext_aes, iv, tag;
        TEST_ASSERT(aes_encrypt(shared_secret_client, plaintext, ciphertext_aes, iv, tag),
                   "AES encryption failed");
        
        print_hex(ciphertext_aes, "Encrypted Message");
        print_hex(iv, "IV");
        print_hex(tag, "Auth Tag");
        
        // Server decrypts using the shared secret
        std::vector<uint8_t> decrypted;
        TEST_ASSERT(aes_decrypt(shared_secret_server, ciphertext_aes, iv, tag, decrypted),
                   "AES decryption failed");
        
        std::string decrypted_message(decrypted.begin(), decrypted.end());
        std::cout << "  Decrypted Message: \"" << decrypted_message << "\"\n";
        
        // Verify the messages match
        TEST_ASSERT(message == decrypted_message, "Decrypted message does not match original!");
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}
// ============================================================================
//  TEST 3: A/B Testing - ML-KEM-512 vs ML-KEM-1024
// ============================================================================
// Compare two different ML-KEM variants:
//   Scenario A: ML-KEM-512 (faster, smaller keys, moderate security)
//   Scenario B: ML-KEM-1024 (slower, larger keys, higher security)
// This test verifies both work correctly and shows their differences.
// ============================================================================
static bool test_ab_different_variants() {
    try {
        std::cout << "\n  --- Scenario A: ML-KEM-512 ---\n";
        {
            MlKem kem_a("ML-KEM-512");
            std::vector<uint8_t> pub_a, sec_a;
            kem_a.keypair(pub_a, sec_a);
            
            std::vector<uint8_t> ct_a, ss_client_a;
            kem_a.encaps(pub_a, ct_a, ss_client_a);
            
            std::vector<uint8_t> ss_server_a;
            kem_a.decaps(ct_a, sec_a, ss_server_a);
            
            TEST_ASSERT(ss_client_a == ss_server_a, "ML-KEM-512 shared secrets don't match");
            
            std::cout << "    Public Key Size: " << pub_a.size() << " bytes\n";
            std::cout << "    Secret Key Size: " << sec_a.size() << " bytes\n";
            std::cout << "    Ciphertext Size: " << ct_a.size() << " bytes\n";
            std::cout << "    Shared Secret Size: " << ss_client_a.size() << " bytes\n";
        }
        
        std::cout << "\n  --- Scenario B: ML-KEM-1024 ---\n";
        {
            MlKem kem_b("ML-KEM-1024");
            std::vector<uint8_t> pub_b, sec_b;
            kem_b.keypair(pub_b, sec_b);
            
            std::vector<uint8_t> ct_b, ss_client_b;
            kem_b.encaps(pub_b, ct_b, ss_client_b);
            
            std::vector<uint8_t> ss_server_b;
            kem_b.decaps(ct_b, sec_b, ss_server_b);
            
            TEST_ASSERT(ss_client_b == ss_server_b, "ML-KEM-1024 shared secrets don't match");
            
            std::cout << "    Public Key Size: " << pub_b.size() << " bytes\n";
            std::cout << "    Secret Key Size: " << sec_b.size() << " bytes\n";
            std::cout << "    Ciphertext Size: " << ct_b.size() << " bytes\n";
            std::cout << "    Shared Secret Size: " << ss_client_b.size() << " bytes\n";
        }
        
        std::cout << "\n  ℹ ML-KEM-1024 uses larger keys/ciphertext but provides stronger security\n";
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}
// ============================================================================
//  TEST 4: Error Handling - Invalid Inputs
// ============================================================================
// Test that the implementation properly handles error cases:
//   - Wrong public key size
//   - Wrong ciphertext size
//   - Wrong secret key size
// ============================================================================
static bool test_error_handling() {
    try {
        MlKem kem("ML-KEM-512");
        
        std::vector<uint8_t> pub, sec;
        kem.keypair(pub, sec);
        
        // Test 1: Encapsulation with invalid public key size
        std::vector<uint8_t> bad_pub(pub.size() - 10);  // Wrong size
        std::vector<uint8_t> ct, ss;
        TEST_ASSERT(!kem.encaps(bad_pub, ct, ss), 
                   "Encapsulation should fail with wrong public key size");
        std::cout << "  ✓ Correctly rejected invalid public key size\n";
        
        // Test 2: Decapsulation with invalid ciphertext size
        std::vector<uint8_t> good_ct, good_ss;
        kem.encaps(pub, good_ct, good_ss);
        
        std::vector<uint8_t> bad_ct(good_ct.size() - 10);  // Wrong size
        std::vector<uint8_t> ss_out;
        TEST_ASSERT(!kem.decaps(bad_ct, sec, ss_out),
                   "Decapsulation should fail with wrong ciphertext size");
        std::cout << "  ✓ Correctly rejected invalid ciphertext size\n";
        
        // Test 3: Decapsulation with invalid secret key size
        std::vector<uint8_t> bad_sec(sec.size() - 10);  // Wrong size
        TEST_ASSERT(!kem.decaps(good_ct, bad_sec, ss_out),
                   "Decapsulation should fail with wrong secret key size");
        std::cout << "  ✓ Correctly rejected invalid secret key size\n";
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}

// ============================================================================
//  TEST 5: Multiple Independent Sessions
// ============================================================================
// Test that multiple KEM sessions can run independently:
//   - Create two separate keypairs
//   - Perform two separate encapsulations
//   - Verify each produces different shared secrets
//   - Verify cross-decapsulation fails (ciphertext from session A
//     cannot be decapsulated with secret key from session B)
// ============================================================================
static bool test_multiple_sessions() {
    try {
        MlKem kem("ML-KEM-512");
        
        // Session 1
        std::vector<uint8_t> pub1, sec1;
        kem.keypair(pub1, sec1);
        
        std::vector<uint8_t> ct1, ss1_client;
        kem.encaps(pub1, ct1, ss1_client);
        
        std::vector<uint8_t> ss1_server;
        kem.decaps(ct1, sec1, ss1_server);
        
        TEST_ASSERT(ss1_client == ss1_server, "Session 1 shared secrets don't match");
        
        // Session 2
        std::vector<uint8_t> pub2, sec2;
        kem.keypair(pub2, sec2);
        
        std::vector<uint8_t> ct2, ss2_client;
        kem.encaps(pub2, ct2, ss2_client);
        
        std::vector<uint8_t> ss2_server;
        kem.decaps(ct2, sec2, ss2_server);
        
        TEST_ASSERT(ss2_client == ss2_server, "Session 2 shared secrets don't match");
        
        // Verify sessions are independent (different shared secrets)
        TEST_ASSERT(ss1_client != ss2_client, "Sessions should produce different shared secrets");
        std::cout << "  ✓ Two independent sessions produced different shared secrets\n";
        // Verify cross-session decapsulation produces wrong results
        std::vector<uint8_t> wrong_ss;
        kem.decaps(ct1, sec2, wrong_ss);  // Use ciphertext from session 1 with key from session 2
        TEST_ASSERT(wrong_ss != ss1_client, 
                   "Cross-session decapsulation should produce wrong shared secret");
        std::cout << "  ✓ Cross-session decapsulation correctly produces different secret\n";
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}

// ============================================================================
//  TEST 6: HKDF Key Derivation
// ============================================================================
// Test the HKDF function for deriving multiple keys from shared secret:
//   - Derive encryption key
//   - Derive MAC key
//   - Verify they are different
// ============================================================================
static bool test_hkdf() {
    try {
        MlKem kem("ML-KEM-512");
        
        // Perform KEM to get shared secret
        std::vector<uint8_t> pub, sec;
        kem.keypair(pub, sec);
        
        std::vector<uint8_t> ct, shared_secret;
        kem.encaps(pub, ct, shared_secret);
        
        // Derive two different keys using HKDF with different info strings
        std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
        
        std::vector<uint8_t> enc_key;
        std::vector<uint8_t> info_enc = {'e', 'n', 'c'};
        TEST_ASSERT(MlKem::hkdf_sha256(shared_secret, salt, info_enc, 32, enc_key),
                   "HKDF derivation for encryption key failed");
        
        std::vector<uint8_t> mac_key;
        std::vector<uint8_t> info_mac = {'m', 'a', 'c'};
        TEST_ASSERT(MlKem::hkdf_sha256(shared_secret, salt, info_mac, 32, mac_key),
                   "HKDF derivation for MAC key failed");
        
        TEST_ASSERT(enc_key.size() == 32, "Encryption key should be 32 bytes");
        TEST_ASSERT(mac_key.size() == 32, "MAC key should be 32 bytes");
        TEST_ASSERT(enc_key != mac_key, "Derived keys should be different");
        
        print_hex(enc_key, "Derived Encryption Key");
        print_hex(mac_key, "Derived MAC Key");
        
        std::cout << "  ✓ HKDF successfully derived two different keys from shared secret\n";
        
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "  Exception: " << ex.what() << "\n";
        return false;
    }
}

// ============================================================================
//  MAIN TEST RUNNER
// ============================================================================
int main() {
    
    // Seed random for AES IV generation
    srand(time(NULL));
    
    // Run all tests
    RUN_TEST(test_basic_kem_workflow);
    RUN_TEST(test_encryption_decryption);
    RUN_TEST(test_ab_different_variants);
    RUN_TEST(test_error_handling);
    RUN_TEST(test_multiple_sessions);
    RUN_TEST(test_hkdf);
    
    // Print summary
    std::cout << "║  TEST SUMMARY                                                  ║\n";
    std::cout << "  Total Tests: " << (tests_passed + tests_failed) << "\n";
    std::cout << "  ✔ Passed: " << tests_passed << "\n";
    std::cout << "  ✘ Failed: " << tests_failed << "\n";
    
    if (tests_failed == 0) {
        std::cout << "\n ALL TESTS PASSED! \n";
        return 0;
    } else {
        std::cout << "\n SOME TESTS FAILED \n";
        return 1;
    }
}
