#include <gtest/gtest.h>
#include "../include/ml_dsa.hpp"
#include "test_helpers.hpp"


TEST(SignVerifyTest, ValidSignaturePasses) {
    MLDSA dsa("ML-DSA-87");

    std::vector<uint8_t> pub, sec;
    ASSERT_TRUE(dsa.generate_keypair(pub, sec));

    std::vector<uint8_t> msg = {'H','e','l','l','o'};
    std::vector<uint8_t> sig;

    ASSERT_TRUE(dsa.sign(sec, msg, sig));
    EXPECT_TRUE(dsa.verify(pub, msg, sig));
}

TEST(SignVerifyTest, ModifiedMessageFails) {
    MLDSA dsa;

    std::vector<uint8_t> pub, sec;
    ASSERT_TRUE(dsa.generate_keypair(pub, sec));

    std::vector<uint8_t> msg = {'A','B','C'};
    std::vector<uint8_t> sig;

    ASSERT_TRUE(dsa.sign(sec, msg, sig));

    msg[0] ^= 0xFF; // tamper message

    EXPECT_FALSE(dsa.verify(pub, msg, sig));
}

TEST(SignVerifyTest, WrongKeySizeFails) {
    MLDSA dsa;

    std::vector<uint8_t> bad_pub = {0,1,2}; // invalid size
    std::vector<uint8_t> msg = {'X'};
    std::vector<uint8_t> sig = {0,1,2};

    EXPECT_FALSE(dsa.verify(bad_pub, msg, sig));
}
