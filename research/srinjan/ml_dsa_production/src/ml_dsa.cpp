#include "ml_dsa.hpp"

#include <oqs/oqs.h>
#include <fstream>
#include <stdexcept>
#include <mutex>
#include <iterator>

// Only base64 is allowed in core (NOT JSON)
#include "../utils/base64.hpp"

using namespace std;

// ======================================================================
//            GLOBAL OQS INITIALIZATION (runs once per process)
// ======================================================================
namespace {

void global_oqs_init() {
    static std::once_flag once;
    std::call_once(once, [] {
        OQS_init(); // CPU feature detection + OQS global init
    });
}

} // anonymous namespace



// ======================================================================
//                           IMPL STRUCT
// ======================================================================
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
            throw std::runtime_error("Failed to instantiate ML-DSA object for: " + alg);
        }
    }

    ~Impl() {
        if (sig) {
            OQS_SIG_free(sig);
            sig = nullptr;
        }
    }
};



// ======================================================================
//                         PUBLIC MLDSA API
// ======================================================================

MLDSA::MLDSA(const std::string &alg_name)
    : pImpl(new Impl(alg_name)) {}

MLDSA::~MLDSA() {
    delete pImpl;
}

std::string MLDSA::algorithm() const {
    return pImpl->alg;
}



// ======================================================================
//                              KEYPAIR
// ======================================================================
bool MLDSA::generate_keypair(std::vector<uint8_t> &public_key,
                             std::vector<uint8_t> &secret_key)
{
    auto sig = pImpl->sig;

    public_key.resize(sig->length_public_key);
    secret_key.resize(sig->length_secret_key);

    OQS_STATUS st = OQS_SIG_keypair(
        sig,
        public_key.data(),
        secret_key.data()
    );

    return st == OQS_SUCCESS;
}



// ======================================================================
//                                SIGN
// ======================================================================
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

    OQS_STATUS st = OQS_SIG_sign(
        sig,
        signature.data(), &sig_len,
        message.data(), message.size(),
        secret_key.data()
    );

    if (st != OQS_SUCCESS) {
        signature.clear();
        return false;
    }

    signature.resize(sig_len);
    return true;
}



// ======================================================================
//                                VERIFY
// ======================================================================
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

    OQS_STATUS st = OQS_SIG_verify(
        sig,
        message.data(), message.size(),
        signature.data(), signature.size(),
        public_key.data()
    );

    return st == OQS_SUCCESS;
}



// ======================================================================
//                        BINARY SAVE / LOAD
// ======================================================================
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



// ======================================================================
//                      JSON SAVE / LOAD  (Format A)
// ======================================================================
//
// This function writes JSON files like:
//
// {
//     "algorithm": "ML-DSA-87",
//     "type": "public" | "secret",
//     "key": "<base64>"
// }
//
// ======================================================================

bool MLDSA::save_key_json(const std::string &filename,
                          std::span<const uint8_t> key,
                          bool is_public) const
{
    // Build JSON manually — NO JSON library used here
    std::ofstream out(filename);
    if (!out) return false;

    out << "{\n";
    out << "  \"algorithm\": \"" << pImpl->alg << "\",\n";
    out << "  \"type\": \"" << (is_public ? "public" : "secret") << "\",\n";
    out << "  \"key\": \"" << mldsa_utils::base64_encode(key) << "\"\n";
    out << "}\n";

    return true;
}


// ======================================================================
//                       JSON LOAD  (Format A)
// ======================================================================
bool MLDSA::load_key_json(const std::string &filename,
                          std::vector<uint8_t> &key,
                          bool &is_public,
                          std::string &algorithm) const
{
    std::ifstream in(filename);
    if (!in) return false;

    // Simple manual JSON parsing (safe for your controlled format)
    std::string file((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());

    auto get_field = [&](const std::string &label) -> std::string {
        size_t pos = file.find(label);
        if (pos == std::string::npos) return "";
        pos = file.find('"', pos + label.size());
        if (pos == std::string::npos) return "";
        size_t end = file.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return file.substr(pos + 1, end - pos - 1);
    };

    algorithm = get_field("algorithm");
    std::string type = get_field("type");
    std::string key_b64 = get_field("key");

    if (algorithm.empty() || type.empty() || key_b64.empty())
        return false;

    is_public = (type == "public");
    key = mldsa_utils::base64_decode(key_b64);

    return !key.empty();
}
