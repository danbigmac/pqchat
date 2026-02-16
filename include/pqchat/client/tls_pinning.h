#pragma once

#include <string>
#include <vector>

#include "pqchat/util/result.h"

namespace pqchat::client {

Result<std::vector<uint8_t>> ParseSha256PinHex(const std::string& pin_hex);

Result<void> VerifyPinnedSha256Fingerprint(
    const std::vector<uint8_t>& fingerprint,
    const std::vector<std::string>& allowed_pins_hex);

}  // namespace pqchat::client

