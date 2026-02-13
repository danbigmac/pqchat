#pragma once

#include <cstdint>
#include <vector>

namespace pqchat::crypto {

class SecureBuffer {
 public:
  SecureBuffer() = default;
  explicit SecureBuffer(size_t size);
  explicit SecureBuffer(std::vector<uint8_t> bytes);

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  ~SecureBuffer();

  [[nodiscard]] const std::vector<uint8_t>& bytes() const { return bytes_; }
  [[nodiscard]] std::vector<uint8_t>& mutable_bytes() { return bytes_; }
  [[nodiscard]] size_t size() const { return bytes_.size(); }

 private:
  void cleanse();

  std::vector<uint8_t> bytes_;
};

}  // namespace pqchat::crypto
