#include "pqchat/client/tls_pinning.h"

#include <algorithm>

#include <openssl/crypto.h>

namespace pqchat::client {
namespace {

bool IsHex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int HexValue(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

}  // namespace

Result<std::vector<uint8_t>> ParseSha256PinHex(const std::string& pin_hex) {
  std::string normalized;
  normalized.reserve(pin_hex.size());
  for (char c : pin_hex) {
    if (c == ':' || c == '-' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      continue;
    }
    if (!IsHex(c)) {
      return Result<std::vector<uint8_t>>::Err("pin contains non-hex characters");
    }
    normalized.push_back(c);
  }

  if (normalized.size() != 64) {
    return Result<std::vector<uint8_t>>::Err("pin must be exactly 32-byte SHA-256 (64 hex chars)");
  }

  std::vector<uint8_t> out;
  out.reserve(32);
  for (size_t i = 0; i < normalized.size(); i += 2) {
    int hi = HexValue(normalized[i]);
    int lo = HexValue(normalized[i + 1]);
    if (hi < 0 || lo < 0) {
      return Result<std::vector<uint8_t>>::Err("invalid pin hex");
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(out));
}

Result<void> VerifyPinnedSha256Fingerprint(
    const std::vector<uint8_t>& fingerprint,
    const std::vector<std::string>& allowed_pins_hex) {
  if (allowed_pins_hex.empty()) {
    return Result<void>::Ok();
  }
  if (fingerprint.size() != 32) {
    return Result<void>::Err("unexpected certificate fingerprint size");
  }

  bool any_valid_pin = false;
  for (const auto& pin_hex : allowed_pins_hex) {
    auto parsed = ParseSha256PinHex(pin_hex);
    if (!parsed.ok()) {
      return Result<void>::Err("invalid configured TLS pin: " + parsed.error());
    }
    any_valid_pin = true;
    const auto& pin = parsed.value();
    if (pin.size() == fingerprint.size() &&
        CRYPTO_memcmp(pin.data(), fingerprint.data(), fingerprint.size()) == 0) {
      return Result<void>::Ok();
    }
  }
  if (!any_valid_pin) {
    return Result<void>::Err("no valid TLS pins configured");
  }
  return Result<void>::Err("server certificate pin mismatch");
}

}  // namespace pqchat::client

