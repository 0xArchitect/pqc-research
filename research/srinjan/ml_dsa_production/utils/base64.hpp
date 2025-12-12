#pragma once
#include <vector>
#include <string>
#include <span>

namespace mldsa_utils {

std::string base64_encode(std::span<const uint8_t> data);
std::vector<uint8_t> base64_decode(const std::string &input);

}
