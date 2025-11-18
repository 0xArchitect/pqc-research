#include <iostream>
#include "oqs/oqs.h"

int main() {
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_512)) {
        std::cout << "ML-KEM-512 not enabled\n";
        return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (!kem) {
        std::cout << "Failed to initialize KEM\n";
        return 1;
    }

    std::cout << "Algorithm: " << kem->method_name << std::endl;
    std::cout << "Public key length: " << kem->length_public_key << std::endl;
    std::cout << "Secret key length: " << kem->length_secret_key << std::endl;

    OQS_KEM_free(kem);
    return 0;
}



