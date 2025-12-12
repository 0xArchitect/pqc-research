#include "ml_dsa.hpp"
#include "../utils/ml_dsa_json.hpp"
#include "../utils/base64.hpp"

#include <iostream>

int main() {
    try {
        MLDSA signer("ML-DSA-87");

        std::vector<uint8_t> pub, sec;
        signer.generate_keypair(pub, sec);

        std::vector<uint8_t> message = {'H','e','l','l','o'};
        std::vector<uint8_t> sig;

        if (!signer.sign(sec, message, sig)) {
    std::cerr << "Signing failed!\n";
    return 1;
}


        bool ok = signer.verify(pub, message, sig);
        std::cout << "Signature verify: " << (ok ? "OK\n" : "FAIL\n");

        std::string json_out =
            mldsa_utils::to_json_keypair_signature(
                signer.algorithm(), pub, sec, sig);

        auto parsed = mldsa_utils::from_json_keypair_signature(json_out);

        bool ok2 = signer.verify(parsed.public_key, message, parsed.signature);
        std::cout << "Verify after JSON round-trip: " << (ok2 ? "OK\n" : "FAIL\n");

    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << "\n";
    }
}
