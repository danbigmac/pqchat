#pragma once

#include <cstdint>
#include <vector>

#include "pqchat/util/result.h"

namespace pqchat::crypto {

Result<std::vector<uint8_t>> Sha256(const std::vector<uint8_t>& data);

}  // namespace pqchat::crypto
