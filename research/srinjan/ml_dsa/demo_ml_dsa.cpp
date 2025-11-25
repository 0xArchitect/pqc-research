#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include "ml_dsa.hpp"

// Helper function to print key or signature in hex format
static void print_hex(const std::vector<uint8_t> &data, const std::string &label) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::string alg = "ML-DSA-44";

    // Instantiate ML-DSA object using given algorithm
    MlDsa dsa(alg);

    // ==================== KEY GENERATION ====================
    // Server creates a signing keypair
    std::vector<uint8_t> pub, sec;
    dsa.keypair(pub, sec);

    print_hex(pub, "Public Key");
    print_hex(sec, "Secret Key");

    // ==================== MESSAGE ============================
    std::string msg_str = "Quantum-safe message signed with ML-DSA";

    // Convert string → byte array
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

    // ==================== SIGNING ============================
    // Client produces signature using secret key
    std::vector<uint8_t> sig;
    dsa.sign(message, sig, sec);
    print_hex(sig, "Signature");

    // ==================== VERIFICATION =======================
    // Server verifies signature using public key
    bool ok = dsa.verify(message, sig, pub);
    std::cout << (ok ? "✔ Verified successfully" : "❌ Verification failed") << "\n";

    // ==================== ATTACK TEST ========================
    // Flip ONE bit of the message
    message[0] ^= 1;

    // Now signature SHOULD fail
    bool ok2 = dsa.verify(message, sig, pub);

    std::cout << (ok2 ?
                  "❌ WRONG! Modified message incorrectly verified!" :
                  "✔ Correct behavior — tampered message was REJECTED") << "\n";
}
