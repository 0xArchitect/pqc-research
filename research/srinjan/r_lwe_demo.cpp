#include <iostream>
#include <vector>
#include <random>
#include <cstdint>
#include <cassert>

using i64 = int64_t;

// Ring parameters
const int n = 8;          // polynomial degree
const i64 q = 97;         // modulus
const int NOISE_BOUND = 1;

// RNG
std::mt19937 rng(std::random_device{}());

// mod q
i64 modq(i64 x) {
    i64 r = x % q;
    if (r < 0) r += q;
    return r;
}

// sample small noise polynomial
std::vector<i64> sample_small_poly() {
    std::uniform_int_distribution<int> dist(-NOISE_BOUND, NOISE_BOUND);
    std::vector<i64> v(n);
    for (int i = 0; i < n; i++) {
        v[i] = dist(rng);
    }
    return v;
}

// sample uniform polynomial
std::vector<i64> sample_uniform_poly() {
    std::uniform_int_distribution<i64> dist(0, q - 1);
    std::vector<i64> v(n);
    for (int i = 0; i < n; i++) {
        v[i] = dist(rng);
    }
    return v;
}

// polynomial multiplication in R_q[x]/(x^n + 1)
std::vector<i64> poly_mul(const std::vector<i64> &a,
                          const std::vector<i64> &b) {
    std::vector<i64> res(n, 0);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int k = (i + j) % n;
            i64 sign = ((i + j) >= n) ? -1 : 1; 
            res[k] = modq(res[k] + sign * a[i] * b[j]);
        }
    }
    return res;
}

void print_poly(const std::vector<i64> &p, const std::string &label) {
    std::cout << label << ": [ ";
    for (auto x : p) std::cout << x << " ";
    std::cout << "]\n";
}

int main() {
    std::cout << "[R-LWE Toy Demo]\n";

    // secret polynomial s
    auto s = sample_small_poly();

    // a polynomial used as "public parameter"
    auto a = sample_uniform_poly();

    // error
    auto e = sample_small_poly();

    // b = a*s + e
    auto as = poly_mul(a, s);
    std::vector<i64> b(n);
    for (int i = 0; i < n; i++) b[i] = modq(as[i] + e[i]);

    print_poly(s, "Secret s");
    print_poly(a, "Public a");
    print_poly(b, "Public b");

    std::cout << "\nEncryption test...\n";
    for (int bit = 0; bit < 2; bit++) {

        // random binary polynomial r
        auto r = sample_uniform_poly();
        for (int i = 0; i < n; i++) r[i] = r[i] & 1;

        auto u = poly_mul(a, r);
        auto br = poly_mul(b, r);

        // encode bit:
        i64 enc = (q / 2) * (bit ? 1 : 0);

        std::vector<i64> v(n);
        for (int i = 0; i < n; i++) {
            v[i] = modq(br[i] + enc);
        }

        // decrypt:
        auto uts = poly_mul(u, s);

        // ideally: v[i] - uts[i] ≈ enc
        std::vector<i64> diff(n);
        for (int i = 0; i < n; i++) {
            diff[i] = modq(v[i] - uts[i]);
        }

        i64 avg = 0;
        for (auto x : diff) avg += x;
        avg /= n;

        int rec = (avg > (q / 4)) ? 1 : 0;

        std::cout << "msg=" << bit << " recovered=" << rec << "\n";
    }
}
