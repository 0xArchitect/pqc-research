#include "base64.hpp"

namespace mldsa_utils {

static constexpr char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(std::span<const uint8_t> data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t v = (data[i] << 16) |
                     (data[i + 1] << 8) |
                     (data[i + 2]);
        i += 3;

        out.push_back(B64_TABLE[(v >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 6) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 0) & 0x3F]);
    }

    if (i + 1 == data.size()) {
        uint32_t v = data[i] << 16;
        out.push_back(B64_TABLE[(v >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == data.size()) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(B64_TABLE[(v >> 18) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 12) & 0x3F]);
        out.push_back(B64_TABLE[(v >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

// ---------------- decode -----------------

std::vector<uint8_t> base64_decode(const std::string &input)
{
    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<uint8_t> out;
    int val = 0, valb = -8;

    for (unsigned char c : input) {
        if (c == '=') break;
        int d = decode_char(c);
        if (d < 0) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

} // namespace mldsa_utils
