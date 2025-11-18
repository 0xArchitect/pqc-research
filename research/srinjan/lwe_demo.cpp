// lwe_demo.cpp
// Toy LWE (Regev-style) demo. Educational only — NOT secure.
// Compile with your project's CMake / make.

#include <iostream>
#include <vector>
#include <random>
#include <cstdint>
#include <cassert>

using i64 = int64_t;

// ---------- PARAMETERS (tiny, for demo) ----------
const int n = 8;           // secret dimension
const int m = 16;          // number of LWE samples (rows of A)
const i64 q = 97;          // modulus (prime-ish for demo)
const int NOISE_BOUND = 1; // uniform noise in [-NOISE_BOUND, NOISE_BOUND]

// ---------- Utilities ----------
i64 modq(i64 x) {
    i64 r = x % q;
    if (r < 0) r += q;
    return r;
}

std::vector<i64> sample_uniform_vector(int len, i64 mod, std::mt19937 &rng) {
    std::uniform_int_distribution<i64> dist(0, mod-1);
    std::vector<i64> v(len);
    for (int i=0;i<len;i++) v[i] = dist(rng);
    return v;
}

std::vector<i64> sample_small_vector(int len, int bound, std::mt19937 &rng) {
    std::uniform_int_distribution<int> dist(-bound, bound);
    std::vector<i64> v(len);
    for (int i=0;i<len;i++) v[i] = dist(rng);
    return v;
}

std::vector<std::vector<i64>> sample_matrix(int rows, int cols, i64 mod, std::mt19937 &rng) {
    std::vector<std::vector<i64>> A(rows, std::vector<i64>(cols));
    std::uniform_int_distribution<i64> dist(0, mod-1);
    for (int i=0;i<rows;i++) for (int j=0;j<cols;j++) A[i][j] = dist(rng);
    return A;
}

std::vector<i64> mat_vec_mul(const std::vector<std::vector<i64>> &A, const std::vector<i64> &v) {
    int rows = (int)A.size();
    int cols = (int)A[0].size();
    assert((int)v.size() == cols);
    std::vector<i64> out(rows, 0);
    for (int i=0;i<rows;i++) {
        i64 acc = 0;
        for (int j=0;j<cols;j++) acc += A[i][j] * v[j];
        out[i] = modq(acc);
    }
    return out;
}

i64 vec_dot(const std::vector<i64> &a, const std::vector<i64> &b) {
    assert(a.size() == b.size());
    i64 s = 0;
    for (size_t i=0;i<a.size();i++) s += a[i] * b[i];
    return modq(s);
}

// ---------- LWE keygen/encrypt/decrypt ----------
struct LWEPublicKey { std::vector<std::vector<i64>> A; std::vector<i64> b; };
using LWESecretKey = std::vector<i64>;

void keygen(LWEPublicKey &pk, LWESecretKey &sk, std::mt19937 &rng) {
    sk = sample_uniform_vector(n, q, rng);                 // secret s in Z_q^n
    pk.A = sample_matrix(m, n, q, rng);                    // A in Z_q^{m x n}
    auto e = sample_small_vector(m, NOISE_BOUND, rng);     // small noise
    auto As = mat_vec_mul(pk.A, sk);                       // A * s
    pk.b.resize(m);
    for (int i=0;i<m;i++) pk.b[i] = modq(As[i] + e[i]);    // b = A s + e (mod q)
}

struct LWECiphertext { std::vector<i64> u; i64 v; };

LWECiphertext encrypt(const LWEPublicKey &pk, int message_bit, std::mt19937 &rng) {
    // message_bit is 0 or 1
    // pick r from {0,1}^m (sparse binary)
    std::vector<i64> r(m);
    std::uniform_int_distribution<int> bit(0,1);
    for (int i=0;i<m;i++) r[i] = bit(rng);

    // u = A^T * r (n-vector)
    std::vector<i64> u(n, 0);
    for (int j=0;j<n;j++) {
        i64 acc = 0;
        for (int i=0;i<m;i++) acc += pk.A[i][j] * r[i];
        u[j] = modq(acc);
    }

    // v = b^T r + encode(message) + small noise
    i64 br = vec_dot(pk.b, r);
    std::uniform_int_distribution<int> noise(-NOISE_BOUND, NOISE_BOUND);
    i64 e2 = noise(rng);
    i64 enc = (q/2) * (message_bit ? 1 : 0); // encode 1 as q/2
    i64 v = modq(br + enc + e2);

    return {u, v};
}

int decrypt(const LWESecretKey &sk, const LWECiphertext &ct) {
    // compute v - u^T s (mod q)
    i64 uts = vec_dot(ct.u, sk);
    i64 diff = modq(ct.v - uts);

    // center to [-q/2, q/2)
    i64 center = diff;
    if (center > q/2) center -= q;

    // decide: near 0 -> 0, near q/2 -> 1
    // threshold halfway (q/4)
    if (std::llabs(center) < q/4) return 0;
    else return 1;
}

// ---------- Demo ----------
int main() {
    std::random_device rd;
    std::mt19937 rng(rd());

    LWEPublicKey pk;
    LWESecretKey sk;
    keygen(pk, sk, rng);

    std::cout << "[LWE toy] parameters: n="<<n<<" m="<<m<<" q="<<q<<" noise_bound="<<NOISE_BOUND<<"\n";
    std::cout << "secret s: ";
    for (auto x: sk) std::cout << x << " ";
    std::cout << "\n";

    for (int bitVal=0; bitVal<2; ++bitVal) {
        auto ct = encrypt(pk, bitVal, rng);
        int rec = decrypt(sk, ct);
        std::cout << "msg="<<bitVal<<" rec="<<rec<<"\n";
    }

    return 0;
}
