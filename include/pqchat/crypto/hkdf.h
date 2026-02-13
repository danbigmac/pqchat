#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pqchat/util/result.h"

namespace pqchat::crypto {

Result<std::vector<uint8_t>> HkdfSha256(const std::vector<uint8_t>& ikm,
                                        const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& info,
                                        size_t output_len);

Result<std::vector<uint8_t>> HmacSha256(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& data);

std::vector<uint8_t> Concat(const std::vector<std::vector<uint8_t>>& parts);
std::vector<uint8_t> ToBytes(const std::string& value);

}  // namespace pqchat::crypto
