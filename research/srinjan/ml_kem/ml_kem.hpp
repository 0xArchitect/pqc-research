#pragma once
#include <string>
#include <vector>
#include <memory>

class MlKem {
public:
    explicit MlKem(const std::string &alg_name = "ML-KEM-512");
    ~MlKem();

    MlKem(const MlKem&) = delete;
    MlKem& operator=(const MlKem&) = delete;

    bool keypair(std::vector<uint8_t> &pubkey,
                 std::vector<uint8_t> &seckey);

    bool encaps(const std::vector<uint8_t> &pubkey,
                std::vector<uint8_t> &ciphertext,
                std::vector<uint8_t> &shared_secret);

    bool decaps(const std::vector<uint8_t> &ciphertext,
                const std::vector<uint8_t> &seckey,
                std::vector<uint8_t> &shared_secret);

    static bool hkdf_sha256(const std::vector<uint8_t> &secret,
                            const std::vector<uint8_t> &salt,
                            const std::vector<uint8_t> &info,
                            size_t out_len,
                            std::vector<uint8_t> &out);

private:
    struct Impl;
    std::unique_ptr<Impl> p;
};
