#include <iostream>
#include <vector>
#include <iomanip>
#include "ml_kem.hpp"

// Helper to print bytes in hex (for debugging)
static void print_hex(const std::vector<uint8_t> &data, const std::string &label) {
    std::cout << label << " (len=" << data.size() << "): ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b);
    }
    std::cout << std::dec << "\n";
}

int main() {
    try {
        // ------------------------------------------------------------
        //  ML-KEM Demo  
        //
        //  This demonstrates a full post-quantum secure handshake:
        //      1️⃣ Keypair (server)
        //      2️⃣ Encapsulation (client)
        //      3️⃣ Decapsulation (server)
        //      4️⃣ Both sides derive the same shared secret
        //
        //  Expected console structure:
        //
        //      === ML-KEM Demo ===
        //      Algorithm: ML-KEM-512
        //
        //      Public Key (len=808):   <hex bytes…>
        //      Secret Key (len=1632):  <hex bytes…>
        //
        //      Ciphertext (len=768):   <hex bytes…>
        //      Shared Secret (Client): <hex bytes…>
        //      Shared Secret (Server): <hex bytes…>
        //
        //      ✔ Shared secret matches! Secure channel established.
        //
        // ------------------------------------------------------------

        std::string alg = "ML-KEM-512";
        MlKem kem(alg);

        std::cout << "=== ML-KEM Demo ===\n";
        std::cout << "Algorithm: " << alg << "\n\n";

        // ------------------------------------------------------------
        // 1. Keypair Generation (Server-side)
        //
        // Output:
        //  - Public Key      → sent to client
        //  - Secret Key      → stays on server
        // ------------------------------------------------------------
        std::vector<uint8_t> pub, sec;
        kem.keypair(pub, sec);

        print_hex(pub, "Public Key");
        print_hex(sec, "Secret Key");
        std::cout << "\n";

        // ------------------------------------------------------------
        // 2. Encapsulation (Client side)
        //
        // Using the server's public key:
        //   - Client produces ciphertext C
        //   - Client derives shared_secret_client
        //
        // Client sends only:
        //      ciphertext → to server
        //
        // Output:
        //  - Ciphertext               (sent to server)
        //  - Shared Secret (Client)   (must match server)
        // ------------------------------------------------------------
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_secret_client;

        kem.encaps(pub, ciphertext, shared_secret_client);

        print_hex(ciphertext, "Ciphertext");
        print_hex(shared_secret_client, "Shared Secret (Client)");
        std::cout << "\n";

        // ------------------------------------------------------------
        // 3. Decapsulation (Server side)
        //
        // Using:
        //   - ciphertext from client
        //   - secret key (server)
        //
        // Server computes:
        //      shared_secret_server
        //
        // Output:
        //  - Shared Secret (Server)
        // ------------------------------------------------------------
        std::vector<uint8_t> shared_secret_server;
        kem.decaps(ciphertext, sec, shared_secret_server);

        print_hex(shared_secret_server, "Shared Secret (Server)");
        std::cout << "\n";

        // ------------------------------------------------------------
        // 4. Verification Step
        //
        // Both shared secrets MUST match:
        //   shared_secret_client == shared_secret_server
        //
        // Expected output:
        //      ✔ Shared secret matches! Secure channel established.
        // ------------------------------------------------------------
        if (shared_secret_client == shared_secret_server) {
            std::cout << "✔ Shared secret matches! Secure channel established.\n";
        } else {
            std::cout << "❌ ERROR: Shared secrets DO NOT match.\n";
        }

    } catch (const std::exception &ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
