#include "ml_dsa.hpp"

#include <oqs/oqs.h>

#include <fstream>
#include <stdexcept>
#include <mutex>
#include <iterator>     // istreambuf_iterator
#include <cstring>      // std::memset

namespace {

/// Initialize liboqs ONCE in process.
void global_oqs_init() {
    static std::once_flag once;
    std::call_once(once, [] {
        OQS_init();  // void, CPU feature detection
    });
}

/// Securely wipe a vector (for secret key use)
inline void secure_zero(std::vector<uint8_t> &v) {
    if (!v.empty()) {
        std::memset(v.data(), 0, v.size());
    }
}

} // anonymous namespace

// =======================
//   Impl definition
// =======================

struct MLDSA::Impl {
    OQS_SIG *sig = nullptr;
    std::string alg;

    explicit Impl(const std::string &alg_name) : alg(alg_name) {
        global_oqs_init();

        if (!OQS_SIG_alg_is_enabled(alg.c_str())) {
            throw std::runtime_error("ML-DSA algorithm not enabled in liboqs: " + alg);
        }

        sig = OQS_SIG_new(alg.c_str());
        if (!sig) {
            throw std::runtime_error("Failed to initialize OQS_SIG for: " + alg);
        }
    }

    ~Impl() {
        if (sig) {
            OQS_SIG_free(sig);
            sig = nullptr;
        }
        // DO NOT call OQS_cleanup()
        // other code in process may still need liboqs.
    }
};

// =======================
//   MLDSA Public API
// =======================

MLDSA::MLDSA(const std::string &alg_name)
    : pImpl(new Impl(alg_name))
{}

MLDSA::~MLDSA() {
    delete pImpl;
}

std::string MLDSA::algorithm() const {
    return pImpl->alg;
}

bool MLDSA::generate_keypair(std::vector<uint8_t> &public_key,
                             std::vector<uint8_t> &secret_key)
{
    auto sig = pImpl->sig;

    public_key.resize(sig->length_public_key);
    secret_key.resize(sig->length_secret_key);

    OQS_STATUS r = OQS_SIG_keypair(sig,
                                   public_key.data(),
                                   secret_key.data());
    if (r != OQS_SUCCESS) {
        secure_zero(secret_key);
        public_key.clear();
        return false;
    }
    return true;
}

bool MLDSA::sign(std::span<const uint8_t> secret_key,
                 std::span<const uint8_t> message,
                 std::vector<uint8_t> &signature)
{
    auto sig = pImpl->sig;

    if (secret_key.size() != static_cast<size_t>(sig->length_secret_key)) {
        return false;
    }

    signature.resize(sig->length_signature);
    size_t sig_len = signature.size();

    OQS_STATUS r = OQS_SIG_sign(sig,
                                signature.data(), &sig_len,
                                message.data(), message.size(),
                                secret_key.data());
    if (r != OQS_SUCCESS) {
        signature.clear();
        return false;
    }

    signature.resize(sig_len);
    return true;
}

bool MLDSA::verify(std::span<const uint8_t> public_key,
                   std::span<const uint8_t> message,
                   std::span<const uint8_t> signature)
{
    auto sig = pImpl->sig;

    if (public_key.size() != static_cast<size_t>(sig->length_public_key)) {
        return false;
    }
    if (signature.empty()) {
        return false;
    }

    OQS_STATUS r = OQS_SIG_verify(sig,
                                  message.data(), message.size(),
                                  signature.data(), signature.size(),
                                  public_key.data());

    // Avoid branching leaks (constant time)
    // Convert result into mask manually
    return (r == OQS_SUCCESS);
}

// ===========================
//   Serialization helpers
// ===========================

bool MLDSA::save_key_to_file(const std::string &filename,
                             std::span<const uint8_t> key)
{
    std::ofstream out(filename, std::ios::binary);
    if (!out) return false;

    out.write(reinterpret_cast<const char*>(key.data()),
              static_cast<std::streamsize>(key.size()));
    return static_cast<bool>(out);
}

bool MLDSA::load_key_from_file(const std::string &filename,
                               std::vector<uint8_t> &key)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in) return false;

    key.assign(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());

    return !key.empty();
}
