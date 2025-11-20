// lwe.cpp
// ⚠️ Educational toy LWE implementation – NOT production secure.

#include "lwe.h"

#include <vector>
#include <random>
#include <cstdint>
#include <cassert>
#include <cmath>

using std::vector;

// ---------- Toy parameters ----------
static const int   LWE_N = 8;          // secret dimension
static const int   LWE_M = 16;         // number of samples
static const i64   LWE_Q = 97;         // modulus
static const int   NOISE_BOUND = 1;    // noise in [-1, 1]

// single RNG for this translation unit
static std::mt19937 &global_rng() {
    static std::mt19937 rng(std::random_device{}());
    return rng;
}

// ---------- Helpers ----------
static i64 modq(i64 x) {
    i64 r = x % LWE_Q;
    if (r < 0) r += LWE_Q;
    return r;
}

static vector<i64> sample_uniform_vector(int len, i64 mod) {
    auto &rng = global_rng();
    std::uniform_int_distribution<i64> dist(0, mod - 1);
    vector<i64> v(len);
    for (int i = 0; i < len; i++) v[i] = dist(rng);
    return v;
}

static vector<i64> sample_small_vector(int len, int bound) {
    auto &rng = global_rng();
    std::uniform_int_distribution<int> dist(-bound, bound);
    vector<i64> v(len);
    for (int i = 0; i < len; i++) v[i] = dist(rng);
    return v;
}

static vector<vector<i64>> sample_matrix(int rows, int cols, i64 mod) {
    auto &rng = global_rng();
    std::uniform_int_distribution<i64> dist(0, mod - 1);
    vector<vector<i64>> A(rows, vector<i64>(cols));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            A[i][j] = dist(rng);
        }
    }
    return A;
}

static vector<i64> mat_vec_mul(const vector<vector<i64>> &A,
                               const vector<i64> &v) {
    int rows = (int)A.size();
    int cols = (int)A[0].size();
    assert((int)v.size() == cols);
    vector<i64> out(rows, 0);
    for (int i = 0; i < rows; i++) {
        i64 acc = 0;
        for (int j = 0; j < cols; j++) {
            acc += A[i][j] * v[j];
        }
        out[i] = modq(acc);
    }
    return out;
}

static i64 vec_dot(const vector<i64> &a, const vector<i64> &b) {
    assert(a.size() == b.size());
    i64 s = 0;
    for (size_t i = 0; i < a.size(); i++) {
        s += a[i] * b[i];
    }
    return modq(s);
}

// ---------- Public API implementations ----------

void lwe_keygen(LWEPublicKey &pk, LWESecretKey &sk) {
    // secret s ∈ Z_q^n
    sk = sample_uniform_vector(LWE_N, LWE_Q);

    // A ∈ Z_q^{m×n}
    pk.A = sample_matrix(LWE_M, LWE_N, LWE_Q);

    // error e (small)
    auto e = sample_small_vector(LWE_M, NOISE_BOUND);

    // b = A·s + e (mod q)
    auto As = mat_vec_mul(pk.A, sk);
    pk.b.resize(LWE_M);
    for (int i = 0; i < LWE_M; i++) {
        pk.b[i] = modq(As[i] + e[i]);
    }
}

LWECiphertext lwe_encrypt(const LWEPublicKey &pk, int message_bit) {
    auto &rng = global_rng();

    // r ∈ {0,1}^m
    vector<i64> r(LWE_M);
    std::uniform_int_distribution<int> bit_dist(0, 1);
    for (int i = 0; i < LWE_M; i++) {
        r[i] = bit_dist(rng);
    }

    // u = Aᵀ r  (n-vector)
    vector<i64> u(LWE_N, 0);
    for (int j = 0; j < LWE_N; j++) {
        i64 acc = 0;
        for (int i = 0; i < LWE_M; i++) {
            acc += pk.A[i][j] * r[i];
        }
        u[j] = modq(acc);
    }

    // v = bᵀ r + encode(m) + small noise
    i64 br = vec_dot(pk.b, r);
    std::uniform_int_distribution<int> noise_dist(-NOISE_BOUND, NOISE_BOUND);
    i64 e2 = noise_dist(rng);
    i64 enc = (LWE_Q / 2) * (message_bit ? 1 : 0); // 0 → 0, 1 → q/2
    i64 v = modq(br + enc + e2);

    return {u, v};
}

int lwe_decrypt(const LWESecretKey &sk, const LWECiphertext &ct) {
    // compute v - uᵀ s (mod q)
    i64 uts = vec_dot(ct.u, sk);
    i64 diff = modq(ct.v - uts);

    // center in [-q/2, q/2)
    i64 center = diff;
    if (center > LWE_Q / 2) {
        center -= LWE_Q;
    }

    // threshold at q/4
    if (std::llabs(center) < LWE_Q / 4) {
        return 0;
    } else {
        return 1;
    }
}
