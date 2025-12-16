#include <gtest/gtest.h>
#include "../include/ml_dsa.hpp"
#include "test_helpers.hpp"


TEST(JsonRoundTrip, KeyJsonSaveLoadWorks) {
    MLDSA dsa("ML-DSA-87");

    std::vector<uint8_t> pub, sec;
    ASSERT_TRUE(dsa.generate_keypair(pub, sec));

    ASSERT_TRUE(dsa.save_key_json("pub.json", pub, true));
    ASSERT_TRUE(dsa.save_key_json("sec.json", sec, false));

    std::vector<uint8_t> pub2, sec2;
    bool is_pub;
    std::string alg;

    ASSERT_TRUE(dsa.load_key_json("pub.json", pub2, is_pub, alg));
    EXPECT_TRUE(is_pub);
    EXPECT_EQ(alg, "ML-DSA-87");
    EXPECT_EQ(pub, pub2);

    ASSERT_TRUE(dsa.load_key_json("sec.json", sec2, is_pub, alg));
    EXPECT_FALSE(is_pub);
    EXPECT_EQ(sec, sec2);
}
