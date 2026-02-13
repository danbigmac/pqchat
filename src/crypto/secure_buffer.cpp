#include "pqchat/crypto/secure_buffer.h"

#include <openssl/crypto.h>

namespace pqchat::crypto {

SecureBuffer::SecureBuffer(size_t size) : bytes_(size) {}

SecureBuffer::SecureBuffer(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : bytes_(std::move(other.bytes_)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    cleanse();
    bytes_ = std::move(other.bytes_);
  }
  return *this;
}

SecureBuffer::~SecureBuffer() {
  cleanse();
}

void SecureBuffer::cleanse() {
  if (!bytes_.empty()) {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
  }
}

}  // namespace pqchat::crypto
