#pragma once
#include <vector>
#include <cstdint>

using i64 = int64_t;

struct LWEPublicKey {
    std::vector<std::vector<i64>> A;
    std::vector<i64> b;
};

using LWESecretKey = std::vector<i64>;

struct LWECiphertext {
    std::vector<i64> u;
    i64 v;
};

// API
void lwe_keygen(LWEPublicKey &pk, LWESecretKey &sk);
LWECiphertext lwe_encrypt(const LWEPublicKey &pk, int message_bit);
int lwe_decrypt(const LWESecretKey &sk, const LWECiphertext &ct);
