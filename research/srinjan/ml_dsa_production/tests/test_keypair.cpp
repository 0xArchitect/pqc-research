#include <gtest/gtest.h>
#include "../include/ml_dsa.hpp"
#include "test_helpers.hpp"


TEST(KeypairTest, GeneratesValidSizeKeys) {
   MLDSA dsa("ML-DSA-87");
std::vector<uint8_t> pub, sec;
ASSERT_TRUE(dsa.generate_keypair(pub, sec));

EXPECT_GT(pub.size(), 0);
EXPECT_GT(sec.size(), 0);

    

    // Keys should not be all zero
    EXPECT_NE(std::vector<uint8_t>(pub.size(), 0), pub);
    EXPECT_NE(std::vector<uint8_t>(sec.size(), 0), sec);
}

TEST(KeypairTest, MultipleKeypairsAreUnique) {
    MLDSA dsa;

    std::vector<uint8_t> p1, s1, p2, s2;
    ASSERT_TRUE(dsa.generate_keypair(p1, s1));
    ASSERT_TRUE(dsa.generate_keypair(p2, s2));

    EXPECT_NE(p1, p2);
    EXPECT_NE(s1, s2);
}
