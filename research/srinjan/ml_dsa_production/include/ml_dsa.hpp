#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>

/// MLDSA – Production-style wrapper over liboqs ML-DSA (Dilithium family).
/// - Runtime configurable algorithm: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
/// - Hybrid API: std::vector + std::span (C++20)
class MLDSA {
public:
    /// Construct with a chosen ML-DSA variant.
    /// Default: "ML-DSA-87" (highest security).
    explicit MLDSA(const std::string &alg_name = "ML-DSA-87");
    ~MLDSA();

    // Non-copyable (crypto objects should not be copied lightly)
    MLDSA(const MLDSA&) = delete;
    MLDSA& operator=(const MLDSA&) = delete;

    /// Generate public/secret key pair.
    /// public_key.size()  == sig->length_public_key
    /// secret_key.size()  == sig->length_secret_key
    bool generate_keypair(std::vector<uint8_t> &public_key,
                          std::vector<uint8_t> &secret_key);

    // ----------------------------
    //  Core C++20 span-based API
    // ----------------------------

    /// Sign a message using a secret key.
    /// Returns true on success, false if sizes are invalid or liboqs fails.
    [[nodiscard]]
    bool sign(std::span<const uint8_t> secret_key,
              std::span<const uint8_t> message,
              std::vector<uint8_t> &signature);

    /// Verify a signature for a message under a public key.
    /// Returns true if signature is valid, false otherwise.
    [[nodiscard]]
    bool verify(std::span<const uint8_t> public_key,
                std::span<const uint8_t> message,
                std::span<const uint8_t> signature);

    // ------------------------------------
    //  Legacy-friendly std::vector API
    // ------------------------------------

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

    // ----------------------------
    //  Serialization helpers
    // ----------------------------

    /// Write raw key bytes to a file (binary).
    static bool save_key_to_file(const std::string &filename,
                                 std::span<const uint8_t> key);

    /// Read raw key bytes from a file (binary) into a vector.
    static bool load_key_from_file(const std::string &filename,
                                   std::vector<uint8_t> &key);
    bool save_key_json(const std::string &filename,
                   std::span<const uint8_t> key,
                   bool is_public) const;

bool load_key_json(const std::string &filename,
                   std::vector<uint8_t> &key,
                   bool &is_public,
                   std::string &algorithm) const;

    /// Get the configured ML-DSA algorithm name (e.g., "ML-DSA-87").
    std::string algorithm() const;

private:
    struct Impl;
    Impl *pImpl;  // PImpl to hide liboqs types from header
};
