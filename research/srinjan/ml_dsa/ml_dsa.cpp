#include "ml_dsa.hpp"
#include <oqs/oqs.h>
#include <stdexcept>

// Implementation storage for internal OQS pointer & algorithm
struct MlDsa::Impl {
    OQS_SIG *sig = nullptr;   // liboqs signature object
    std::string alg;

    Impl(const std::string &a) : alg(a) {
        // ensure algorithm exists in liboqs
        if (!OQS_SIG_alg_is_enabled(alg.c_str())) {
            throw std::runtime_error("Signature algorithm not enabled: " + alg);
        }

        // allocate algorithm inside liboqs
        sig = OQS_SIG_new(alg.c_str());
        if (!sig)
            throw std::runtime_error("OQS_SIG_new failed");
    }

    ~Impl() {
        // free internal liboqs object
        if (sig) OQS_SIG_free(sig);
    }
};

// Construct ML-DSA wrapper
MlDsa::MlDsa(const std::string &alg_name) : p(nullptr) {
    p.reset(new Impl(alg_name));
}

// default destructor
MlDsa::~MlDsa() = default;

// ======================= KEYPAIR =========================
// Generates (public_key, secret_key)
bool MlDsa::keypair(std::vector<uint8_t> &pubkey,
                    std::vector<uint8_t> &seckey) {

    auto sig = p->sig;

    // resize key buffers to exact algorithm sizes
    pubkey.assign(sig->length_public_key, 0);
    seckey.assign(sig->length_secret_key, 0);

    // call liboqs implementation to generate keypair
    return OQS_SIG_keypair(sig, pubkey.data(), seckey.data()) == OQS_SUCCESS;
}

// ======================= SIGN ============================
// Generates signature over a message using secret key
bool MlDsa::sign(const std::vector<uint8_t> &message,
                 std::vector<uint8_t> &signature,
                 const std::vector<uint8_t> &seckey) {

    auto sig = p->sig;

    // allocate maximum signature buffer
    size_t siglen = sig->length_signature;
    signature.assign(siglen, 0);

    // call liboqs signing function
    return OQS_SIG_sign(sig,
                        signature.data(), &siglen,
                        message.data(), message.size(),
                        seckey.data()) == OQS_SUCCESS;
}

// ======================= VERIFY ==========================
// Check whether signature is valid for a given message and public key
bool MlDsa::verify(const std::vector<uint8_t> &message,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &pubkey) {

    auto sig = p->sig;

    // return OQS_SUCCESS if signature validated
    return OQS_SIG_verify(sig,
                          message.data(), message.size(),
                          signature.data(), signature.size(),
                          pubkey.data()) == OQS_SUCCESS;
}
