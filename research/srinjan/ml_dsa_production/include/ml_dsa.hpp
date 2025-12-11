#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>

class MLDSA {
public:
    explicit MLDSA(const std::string &alg_name = "ML-DSA-87");
    ~MLDSA();

    MLDSA(const MLDSA&) = delete;
    MLDSA& operator=(const MLDSA&) = delete;

    bool generate_keypair(std::vector<uint8_t> &public_key,
                          std::vector<uint8_t> &secret_key);

    [[nodiscard]]
    bool sign(std::span<const uint8_t> secret_key,
              std::span<const uint8_t> message,
              std::vector<uint8_t> &signature);

    [[nodiscard]]
    bool verify(std::span<const uint8_t> public_key,
                std::span<const uint8_t> message,
                std::span<const uint8_t> signature);

    [[nodiscard]]
    bool sign(const std::vector<uint8_t> &secret_key,
              const std::vector<uint8_t> &message,
              std::vector<uint8_t> &signature)
    {
        return sign(std::span<const uint8_t>(secret_key),
                    std::span<const uint8_t>(message),
                    signature);
    }

    [[nodiscard]]
    bool verify(const std::vector<uint8_t> &public_key,
                const std::vector<uint8_t> &message,
                const std::vector<uint8_t> &signature)
    {
        return verify(std::span<const uint8_t>(public_key),
                      std::span<const uint8_t>(message),
                      std::span<const uint8_t>(signature));
    }

    static bool save_key_to_file(const std::string &filename,
                                 std::span<const uint8_t> key);

    static bool load_key_from_file(const std::string &filename,
                                   std::vector<uint8_t> &key);

    bool save_key_json(const std::string &filename,
                       std::span<const uint8_t> key,
                       bool is_public) const;

    bool load_key_json(const std::string &filename,
                       std::vector<uint8_t> &key,
                       bool &is_public,
                       std::string &algorithm) const;

    std::string algorithm() const;

private:
    struct Impl;
    Impl *pImpl;
};
