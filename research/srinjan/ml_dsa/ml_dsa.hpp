#pragma once

#include <string>
#include <vector>
#include <memory>

class MlDsa {
public:
    explicit MlDsa(const std::string &alg_name = "ML-DSA-44");
    ~MlDsa();

    bool keypair(std::vector<uint8_t> &pubkey,
                 std::vector<uint8_t> &seckey);

    bool sign(const std::vector<uint8_t> &message,
              std::vector<uint8_t> &signature,
              const std::vector<uint8_t> &seckey);

    bool verify(const std::vector<uint8_t> &message,
                const std::vector<uint8_t> &signature,
                const std::vector<uint8_t> &pubkey);

private:
    struct Impl;
    std::unique_ptr<Impl> p;
};
