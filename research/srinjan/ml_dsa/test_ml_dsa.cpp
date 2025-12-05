#include <gtest/gtest.h>
#include "ml_dsa.hpp"
#include <vector>
#include <string>
#include <chrono>
#include <stdexcept>

// ============================================================================
// Test Fixture for ML-DSA Tests
// ============================================================================
class MlDsaTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup for each test
    }

    void TearDown() override {
        // Common cleanup for each test
    }

    // Helper: Generate a message of specified size
    std::vector<uint8_t> generate_message(size_t size) {
        std::vector<uint8_t> msg(size);
        for (size_t i = 0; i < size; i++) {
            msg[i] = static_cast<uint8_t>(i % 256);
        }
        return msg;
    }

    // Helper: Verify basic workflow (keypair -> sign -> verify)
    bool test_basic_workflow(const std::string& alg_name, const std::vector<uint8_t>& message) {
        MlDsa dsa(alg_name);
        
        std::vector<uint8_t> pubkey, seckey, signature;
        
        // Generate keypair
        if (!dsa.keypair(pubkey, seckey)) return false;
        
        // Sign message
        if (!dsa.sign(message, signature, seckey)) return false;
        
        // Verify signature
        if (!dsa.verify(message, signature, pubkey)) return false;
        
        return true;
    }
};

// ============================================================================
// BASIC FUNCTIONALITY TESTS
// ============================================================================

TEST_F(MlDsaTest, KeypairGeneration_MLDSA44) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    EXPECT_GT(pubkey.size(), 0);
    EXPECT_GT(seckey.size(), 0);
    // ML-DSA-44 expected sizes: pubkey=1312, seckey=2560
    EXPECT_EQ(pubkey.size(), 1312);
    EXPECT_EQ(seckey.size(), 2560);
}

TEST_F(MlDsaTest, KeypairGeneration_MLDSA65) {
    MlDsa dsa("ML-DSA-65");
    std::vector<uint8_t> pubkey, seckey;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    EXPECT_GT(pubkey.size(), 0);
    EXPECT_GT(seckey.size(), 0);
    // ML-DSA-65 expected sizes: pubkey=1952, seckey=4032
    EXPECT_EQ(pubkey.size(), 1952);
    EXPECT_EQ(seckey.size(), 4032);
}

TEST_F(MlDsaTest, KeypairGeneration_MLDSA87) {
    MlDsa dsa("ML-DSA-87");
    std::vector<uint8_t> pubkey, seckey;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    EXPECT_GT(pubkey.size(), 0);
    EXPECT_GT(seckey.size(), 0);
    // ML-DSA-87 expected sizes: pubkey=2592, seckey=4896
    EXPECT_EQ(pubkey.size(), 2592);
    EXPECT_EQ(seckey.size(), 4896);
}

TEST_F(MlDsaTest, SignAndVerify_BasicMessage) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    // Generate keypair
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // Create a simple message
    std::string msg_str = "Test message for ML-DSA";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    // Sign the message
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_GT(signature.size(), 0);
    
    // Verify the signature
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, FullWorkflow_AllVariants) {
    std::vector<std::string> algorithms = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    std::string msg_str = "Quantum-safe signature test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    for (const auto& alg : algorithms) {
        EXPECT_TRUE(test_basic_workflow(alg, message)) 
            << "Failed for algorithm: " << alg;
    }
}

// ============================================================================
// MESSAGE VARIATION TESTS
// ============================================================================

TEST_F(MlDsaTest, EmptyMessage) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // Empty message
    std::vector<uint8_t> message;
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, SingleByteMessage) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // Single byte message
    std::vector<uint8_t> message = {0x42};
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, LargeMessage_1KB) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // 1 KB message
    auto message = generate_message(1024);
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, LargeMessage_10KB) {
    MlDsa dsa("ML-DSA-65");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // 10 KB message
    auto message = generate_message(10240);
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, LargeMessage_1MB) {
    MlDsa dsa("ML-DSA-87");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    // 1 MB message
    auto message = generate_message(1024 * 1024);
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

TEST_F(MlDsaTest, InvalidAlgorithmName) {
    EXPECT_THROW({
        MlDsa dsa("INVALID-ALGORITHM");
    }, std::runtime_error);
}

TEST_F(MlDsaTest, EmptyAlgorithmName) {
    EXPECT_THROW({
        MlDsa dsa("");
    }, std::runtime_error);
}

// ============================================================================
// NEGATIVE TESTS - Tampering Detection
// ============================================================================

TEST_F(MlDsaTest, TamperedMessage_BitFlip) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Original message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    EXPECT_TRUE(dsa.verify(message, signature, pubkey));
    
    // Tamper with the message (flip one bit)
    message[0] ^= 1;
    
    // Verification should FAIL
    EXPECT_FALSE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, TamperedMessage_ByteChange) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Quantum-safe message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    
    // Tamper with the message (change entire byte)
    message[5] = 0xFF;
    
    // Verification should FAIL
    EXPECT_FALSE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, TamperedSignature_BitFlip) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Message to sign";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    
    // Tamper with the signature
    signature[10] ^= 1;
    
    // Verification should FAIL
    EXPECT_FALSE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, TamperedSignature_TruncatedSignature) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey, signature;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Message to sign";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    
    // Truncate the signature
    signature.resize(signature.size() / 2);
    
    // Verification should FAIL
    EXPECT_FALSE(dsa.verify(message, signature, pubkey));
}

TEST_F(MlDsaTest, WrongPublicKey) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey1, seckey1, signature;
    std::vector<uint8_t> pubkey2, seckey2;
    
    // Generate two different keypairs
    ASSERT_TRUE(dsa.keypair(pubkey1, seckey1));
    ASSERT_TRUE(dsa.keypair(pubkey2, seckey2));
    
    std::string msg_str = "Test message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    // Sign with first secret key
    ASSERT_TRUE(dsa.sign(message, signature, seckey1));
    
    // Verify with WRONG public key (should fail)
    EXPECT_FALSE(dsa.verify(message, signature, pubkey2));
    
    // Verify with CORRECT public key (should succeed)
    EXPECT_TRUE(dsa.verify(message, signature, pubkey1));
}

TEST_F(MlDsaTest, WrongSecretKey_DifferentKeypair) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey1, seckey1;
    std::vector<uint8_t> pubkey2, seckey2;
    std::vector<uint8_t> signature;
    
    // Generate two different keypairs
    ASSERT_TRUE(dsa.keypair(pubkey1, seckey1));
    ASSERT_TRUE(dsa.keypair(pubkey2, seckey2));
    
    std::string msg_str = "Test message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    // Sign with second secret key
    ASSERT_TRUE(dsa.sign(message, signature, seckey2));
    
    // Try to verify with first public key (should fail - mismatched keypair)
    EXPECT_FALSE(dsa.verify(message, signature, pubkey1));
    
    // Verify with matching public key (should succeed)
    EXPECT_TRUE(dsa.verify(message, signature, pubkey2));
}

// ============================================================================
// CROSS-VALIDATION TESTS
// ============================================================================

TEST_F(MlDsaTest, CrossAlgorithm_44_to_65) {
    MlDsa dsa44("ML-DSA-44");
    MlDsa dsa65("ML-DSA-65");
    
    std::vector<uint8_t> pubkey44, seckey44, signature44;
    std::vector<uint8_t> pubkey65, seckey65;
    
    ASSERT_TRUE(dsa44.keypair(pubkey44, seckey44));
    ASSERT_TRUE(dsa65.keypair(pubkey65, seckey65));
    
    std::string msg_str = "Cross-algorithm test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    // Sign with ML-DSA-44
    ASSERT_TRUE(dsa44.sign(message, signature44, seckey44));
    
    // Try to verify with ML-DSA-65 (should fail due to different key sizes)
    EXPECT_FALSE(dsa65.verify(message, signature44, pubkey44));
}

TEST_F(MlDsaTest, CrossAlgorithm_65_to_87) {
    MlDsa dsa65("ML-DSA-65");
    MlDsa dsa87("ML-DSA-87");
    
    std::vector<uint8_t> pubkey65, seckey65, signature65;
    std::vector<uint8_t> pubkey87, seckey87;
    
    ASSERT_TRUE(dsa65.keypair(pubkey65, seckey65));
    ASSERT_TRUE(dsa87.keypair(pubkey87, seckey87));
    
    std::string msg_str = "Cross-algorithm test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    // Sign with ML-DSA-65
    ASSERT_TRUE(dsa65.sign(message, signature65, seckey65));
    
    // Try to verify with ML-DSA-87 (should fail due to different key sizes)
    EXPECT_FALSE(dsa87.verify(message, signature65, pubkey65));
}

// ============================================================================
// SIGNATURE INTEGRITY TESTS
// ============================================================================

TEST_F(MlDsaTest, SignatureDeterminism_SameMessage) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Determinism test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    std::vector<uint8_t> sig1, sig2;
    
    ASSERT_TRUE(dsa.sign(message, sig1, seckey));
    ASSERT_TRUE(dsa.sign(message, sig2, seckey));
    
    // ML-DSA may produce different signatures for same message (randomized)
    // But both should verify correctly
    EXPECT_TRUE(dsa.verify(message, sig1, pubkey));
    EXPECT_TRUE(dsa.verify(message, sig2, pubkey));
}

TEST_F(MlDsaTest, MultipleSignatures_DifferentMessages) {
    MlDsa dsa("ML-DSA-44");
    std::vector<uint8_t> pubkey, seckey;
    
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    for (int i = 0; i < 10; i++) {
        std::string msg_str = "Message number " + std::to_string(i);
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
        std::vector<uint8_t> signature;
        
        ASSERT_TRUE(dsa.sign(message, signature, seckey));
        EXPECT_TRUE(dsa.verify(message, signature, pubkey));
    }
}

// ============================================================================
// MULTIPLE INSTANCE TESTS
// ============================================================================

TEST_F(MlDsaTest, MultipleInstances_Concurrent) {
    MlDsa dsa1("ML-DSA-44");
    MlDsa dsa2("ML-DSA-65");
    MlDsa dsa3("ML-DSA-87");
    
    std::vector<uint8_t> pk1, sk1, sig1;
    std::vector<uint8_t> pk2, sk2, sig2;
    std::vector<uint8_t> pk3, sk3, sig3;
    
    ASSERT_TRUE(dsa1.keypair(pk1, sk1));
    ASSERT_TRUE(dsa2.keypair(pk2, sk2));
    ASSERT_TRUE(dsa3.keypair(pk3, sk3));
    
    std::string msg_str = "Concurrent instance test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa1.sign(message, sig1, sk1));
    ASSERT_TRUE(dsa2.sign(message, sig2, sk2));
    ASSERT_TRUE(dsa3.sign(message, sig3, sk3));
    
    EXPECT_TRUE(dsa1.verify(message, sig1, pk1));
    EXPECT_TRUE(dsa2.verify(message, sig2, pk2));
    EXPECT_TRUE(dsa3.verify(message, sig3, pk3));
}

TEST_F(MlDsaTest, MultipleInstances_SameAlgorithm) {
    MlDsa dsa1("ML-DSA-44");
    MlDsa dsa2("ML-DSA-44");
    
    std::vector<uint8_t> pk1, sk1, sig1;
    std::vector<uint8_t> pk2, sk2, sig2;
    
    ASSERT_TRUE(dsa1.keypair(pk1, sk1));
    ASSERT_TRUE(dsa2.keypair(pk2, sk2));
    
    std::string msg_str = "Multiple instance test";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa1.sign(message, sig1, sk1));
    ASSERT_TRUE(dsa2.sign(message, sig2, sk2));
    
    // Each instance should verify its own signatures
    EXPECT_TRUE(dsa1.verify(message, sig1, pk1));
    EXPECT_TRUE(dsa2.verify(message, sig2, pk2));
    
    // Cross-verification should work within same algorithm
    EXPECT_TRUE(dsa1.verify(message, sig2, pk2));
    EXPECT_TRUE(dsa2.verify(message, sig1, pk1));
}

// ============================================================================
// PERFORMANCE BENCHMARKS
// ============================================================================

TEST_F(MlDsaTest, DISABLED_Benchmark_KeypairGeneration) {
    const int iterations = 100;
    MlDsa dsa("ML-DSA-44");
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        std::vector<uint8_t> pubkey, seckey;
        dsa.keypair(pubkey, seckey);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Keypair generation (" << iterations << " iterations): " 
              << duration.count() << " ms" << std::endl;
    std::cout << "Average per keypair: " 
              << (duration.count() / static_cast<double>(iterations)) << " ms" << std::endl;
}

TEST_F(MlDsaTest, DISABLED_Benchmark_Signing) {
    const int iterations = 100;
    MlDsa dsa("ML-DSA-44");
    
    std::vector<uint8_t> pubkey, seckey;
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Performance benchmark message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        std::vector<uint8_t> signature;
        dsa.sign(message, signature, seckey);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Signing (" << iterations << " iterations): " 
              << duration.count() << " ms" << std::endl;
    std::cout << "Average per signature: " 
              << (duration.count() / static_cast<double>(iterations)) << " ms" << std::endl;
}

TEST_F(MlDsaTest, DISABLED_Benchmark_Verification) {
    const int iterations = 100;
    MlDsa dsa("ML-DSA-44");
    
    std::vector<uint8_t> pubkey, seckey, signature;
    ASSERT_TRUE(dsa.keypair(pubkey, seckey));
    
    std::string msg_str = "Performance benchmark message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    
    ASSERT_TRUE(dsa.sign(message, signature, seckey));
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        dsa.verify(message, signature, pubkey);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Verification (" << iterations << " iterations): " 
              << duration.count() << " ms" << std::endl;
    std::cout << "Average per verification: " 
              << (duration.count() / static_cast<double>(iterations)) << " ms" << std::endl;
}

TEST_F(MlDsaTest, DISABLED_Benchmark_AllAlgorithms) {
    std::vector<std::string> algorithms = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    std::string msg_str = "Benchmark message";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
    const int iterations = 50;
    
    for (const auto& alg : algorithms) {
        std::cout << "\n=== " << alg << " ===" << std::endl;
        MlDsa dsa(alg);
        
        // Keypair generation
        auto start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> pubkey, seckey;
        for (int i = 0; i < iterations; i++) {
            dsa.keypair(pubkey, seckey);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Keypair: " << (duration.count() / static_cast<double>(iterations)) << " ms/op" << std::endl;
        
        // Signing
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            std::vector<uint8_t> signature;
            dsa.sign(message, signature, seckey);
        }
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Sign: " << (duration.count() / static_cast<double>(iterations)) << " ms/op" << std::endl;
        
        // Verification
        std::vector<uint8_t> signature;
        dsa.sign(message, signature, seckey);
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; i++) {
            dsa.verify(message, signature, pubkey);
        }
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Verify: " << (duration.count() / static_cast<double>(iterations)) << " ms/op" << std::endl;
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
