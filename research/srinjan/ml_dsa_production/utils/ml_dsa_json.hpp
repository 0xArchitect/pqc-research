#pragma once
#include <string>
#include <vector>

namespace mldsa_utils {

struct KeyJson {
    std::string algorithm;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    std::vector<uint8_t> signature;
};

std::string to_json_keypair_signature(
    const std::string &algorithm,
    const std::vector<uint8_t> &public_key,
    const std::vector<uint8_t> &secret_key,
    const std::vector<uint8_t> &signature);

KeyJson from_json_keypair_signature(const std::string &json_str);

} // namespace mldsa_utils
