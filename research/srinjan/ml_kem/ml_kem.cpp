#include "ml_kem.hpp"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>

struct MlKem::Impl {
    OQS_KEM *kem = nullptr;
    std::string alg;

    Impl(const std::string &a) : alg(a) {
        if (!OQS_KEM_alg_is_enabled(alg.c_str())) {
            throw std::runtime_error("KEM algorithm not enabled: " + alg);
        }
        kem = OQS_KEM_new(alg.c_str());
        if (!kem) throw std::runtime_error("Failed to init KEM: " + alg);
    }

    ~Impl() {
        if (kem) OQS_KEM_free(kem);
    }
};

MlKem::MlKem(const std::string &alg_name) {
    p.reset(new Impl(alg_name));
}
MlKem::~MlKem() = default;

bool MlKem::keypair(std::vector<uint8_t> &pubkey,
                    std::vector<uint8_t> &seckey) {
    auto k = p->kem;
    pubkey.assign(k->length_public_key, 0);
    seckey.assign(k->length_secret_key, 0);
    return OQS_KEM_keypair(k, pubkey.data(), seckey.data())
            == OQS_SUCCESS;
}

bool MlKem::encaps(const std::vector<uint8_t> &pubkey,
                   std::vector<uint8_t> &ciphertext,
                   std::vector<uint8_t> &shared_secret) {
    auto k = p->kem;
    if (pubkey.size() != (size_t)k->length_public_key) return false;

    ciphertext.assign(k->length_ciphertext, 0);
    shared_secret.assign(k->length_shared_secret, 0);

    return OQS_KEM_encaps(k,
            ciphertext.data(),
            shared_secret.data(),
            pubkey.data()) == OQS_SUCCESS;
}

bool MlKem::decaps(const std::vector<uint8_t> &ciphertext,
                   const std::vector<uint8_t> &seckey,
                   std::vector<uint8_t> &shared_secret) {
    auto k = p->kem;
    if (ciphertext.size() != (size_t)k->length_ciphertext) return false;
    if (seckey.size() != (size_t)k->length_secret_key) return false;

    shared_secret.assign(k->length_shared_secret, 0);

    return OQS_KEM_decaps(k,
            shared_secret.data(),
            ciphertext.data(),
            seckey.data()) == OQS_SUCCESS;
}

bool MlKem::hkdf_sha256(const std::vector<uint8_t> &secret,
                        const std::vector<uint8_t> &salt,
                        const std::vector<uint8_t> &info,
                        size_t out_len,
                        std::vector<uint8_t> &out) {

    out.resize(out_len);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return false;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(), secret.size()) <= 0 ||
        (!salt.empty() &&
         EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) <= 0) ||
        (!info.empty() &&
         EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size()) <= 0) ||
        EVP_PKEY_derive(ctx, out.data(), &out_len) <= 0) {

        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}
