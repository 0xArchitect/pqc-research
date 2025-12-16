#include <gtest/gtest.h>
#include "../include/ml_dsa.hpp"
#include <fstream>
#include "test_helpers.hpp"


TEST(JsonInvalid, MissingFieldsFails) {
    MLDSA dsa;

    std::ofstream("bad.json") << R"({
        "algorithm": "ML-DSA-87"
    })";

    std::vector<uint8_t> key;
    bool is_pub;
    std::string alg;

    EXPECT_FALSE(dsa.load_key_json("bad.json", key, is_pub, alg));
}

TEST(JsonInvalid, CorruptedBase64Fails) {
    MLDSA dsa;

    std::ofstream("bad2.json") << R"({
        "algorithm": "ML-DSA-87",
        "type": "public",
        "key": "!@#$%^&*(!@#$"  
    })";

    std::vector<uint8_t> key;
    bool is_pub;
    std::string alg;

    EXPECT_FALSE(dsa.load_key_json("bad2.json", key, is_pub, alg));
}
