#include "ml_dsa_json.hpp"
#include "base64.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace mldsa_utils {

std::string to_json_keypair_signature(
    const std::string &algorithm,
    const std::vector<uint8_t> &public_key,
    const std::vector<uint8_t> &secret_key,
    const std::vector<uint8_t> &signature)
{
    json j;
    j["algorithm"]  = algorithm;
    j["public_key"] = base64_encode(public_key);
    j["secret_key"] = base64_encode(secret_key);
    j["signature"]  = base64_encode(signature);

    return j.dump(4);
}

KeyJson from_json_keypair_signature(const std::string &json_str)
{
    KeyJson out;
    json j = json::parse(json_str);

    if (!j.contains("public_key") ||
        !j.contains("secret_key") ||
        !j.contains("signature"))
        throw std::runtime_error("Invalid JSON: missing fields");

    if (j.contains("algorithm"))
        out.algorithm = j["algorithm"];
    else
        out.algorithm = "UNKNOWN";

    out.public_key = base64_decode(j["public_key"]);
    out.secret_key = base64_decode(j["secret_key"]);
    out.signature  = base64_decode(j["signature"]);

    return out;
}

} // namespace mldsa_utils
