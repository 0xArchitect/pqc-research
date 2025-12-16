#pragma once
#include <string>

struct KeySizes {
    size_t pub;
    size_t sec;
    size_t sig;
};

inline KeySizes dsa_key_size_for(const std::string &alg) {
    if (alg == "ML-DSA-87") {
        return {2592, 4864, 4595};
    }
    if (alg == "ML-DSA-65") {
        return {1952, 4000, 3309};
    }
    if (alg == "ML-DSA-44") {
        return {1312, 2528, 2420};
    }

    return {0, 0, 0};
}
