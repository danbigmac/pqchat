#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <cstring>
#include <iostream>
#include <stdlib.h>
#include <random>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "pqchat/client/client.h"
#include "pqchat/protocol/messages.h"
#include "pqchat/protocol/serialization.h"

namespace {

bool AssertTrue(bool value, const std::string& label) {
  if (!value) {
    std::cerr << "FAIL: " << label << "\n";
    return false;
  }
  return true;
}

bool Contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

uint32_t ReadU32(const std::vector<uint8_t>& bytes, size_t offset) {
  return (static_cast<uint32_t>(bytes[offset]) << 24) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
         static_cast<uint32_t>(bytes[offset + 3]);
}

void WriteU32(std::vector<uint8_t>* bytes, size_t offset, uint32_t value) {
  (*bytes)[offset] = static_cast<uint8_t>((value >> 24) & 0xFF);
  (*bytes)[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  (*bytes)[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  (*bytes)[offset + 3] = static_cast<uint8_t>(value & 0xFF);
}

bool SkipLenPrefixedField(const std::vector<uint8_t>& bytes, size_t* pos) {
  if (*pos + 4 > bytes.size()) {
    return false;
  }
  uint32_t len = ReadU32(bytes, *pos);
  *pos += 4;
  if (*pos + len > bytes.size()) {
    return false;
  }
  *pos += len;
  return true;
}

bool SkipSignedPrekey(const std::vector<uint8_t>& bytes, size_t* pos) {
  if (*pos + 4 > bytes.size()) {
    return false;
  }
  *pos += 4;  // id
  return SkipLenPrefixedField(bytes, pos) && SkipLenPrefixedField(bytes, pos) &&
         SkipLenPrefixedField(bytes, pos);
}

bool TestCountAndLengthLimitRejections() {
  using pqchat::protocol::DeserializeEnvelopeVector;
  using pqchat::protocol::DeserializeInboxEnvelopeVector;
  using pqchat::protocol::DeserializeString;

  std::vector<uint8_t> huge_count = {0x00, 0x00, 0x10, 0x01};
  auto envelope_count = DeserializeEnvelopeVector(huge_count);
  if (!AssertTrue(!envelope_count.ok() &&
                      Contains(envelope_count.error(), "exceeds limit"),
                  "envelope vector count limit")) {
    return false;
  }

  auto inbox_count = DeserializeInboxEnvelopeVector(huge_count);
  if (!AssertTrue(!inbox_count.ok() &&
                      Contains(inbox_count.error(), "exceeds limit"),
                  "inbox envelope vector count limit")) {
    return false;
  }

  std::vector<uint8_t> huge_string = {0x00, 0x01, 0x00, 0x01};
  auto oversized_string = DeserializeString(huge_string);
  return AssertTrue(!oversized_string.ok() &&
                        Contains(oversized_string.error(), "exceeds limit"),
                    "string length limit");
}

bool TestPrekeyCountLimitRejection() {
  using pqchat::client::Client;
  using pqchat::protocol::DeserializePrekeyBundle;
  using pqchat::protocol::SerializePrekeyBundle;

  auto client = Client::Create("alice");
  if (!AssertTrue(client.ok(), "client create for prekey count test")) {
    return false;
  }
  auto encoded = SerializePrekeyBundle(client.value().BuildPrekeyBundle());
  if (!AssertTrue(encoded.ok(), "serialize valid prekey bundle")) {
    return false;
  }

  auto bytes = encoded.take_value();
  size_t pos = 0;
  bool ok = SkipLenPrefixedField(bytes, &pos) &&  // user_id
            SkipLenPrefixedField(bytes, &pos) &&  // identity sign
            SkipLenPrefixedField(bytes, &pos) &&  // identity mldsa
            SkipLenPrefixedField(bytes, &pos) &&  // identity dh
            SkipSignedPrekey(bytes, &pos) &&
            SkipSignedPrekey(bytes, &pos);
  if (!AssertTrue(ok && pos + 4 <= bytes.size(),
                  "locate one-time EC count offset")) {
    return false;
  }

  WriteU32(&bytes, pos, 5000);
  auto decoded = DeserializePrekeyBundle(bytes);
  return AssertTrue(!decoded.ok() &&
                        Contains(decoded.error(), "one-time EC prekey count"),
                    "prekey bundle one-time count limit");
}

bool TestMalformedFuzzHarness() {
  using pqchat::protocol::DeserializeAuthenticatedPayload;
  using pqchat::protocol::DeserializeEnvelope;
  using pqchat::protocol::DeserializeEnvelopeVector;
  using pqchat::protocol::DeserializeInboxEnvelopeVector;
  using pqchat::protocol::DeserializePrekeyBundle;

  std::mt19937 rng(1337);
  std::uniform_int_distribution<int> len_dist(0, 384);
  std::uniform_int_distribution<int> byte_dist(0, 255);
  int err_count = 0;

  for (int i = 0; i < 600; ++i) {
    const int len = len_dist(rng);
    std::vector<uint8_t> bytes(static_cast<size_t>(len), 0);
    for (int j = 0; j < len; ++j) {
      bytes[static_cast<size_t>(j)] = static_cast<uint8_t>(byte_dist(rng));
    }

    auto a = DeserializeEnvelope(bytes);
    auto b = DeserializeEnvelopeVector(bytes);
    auto c = DeserializeInboxEnvelopeVector(bytes);
    auto d = DeserializePrekeyBundle(bytes);
    auto e = DeserializeAuthenticatedPayload(bytes);

    err_count += (!a.ok() ? 1 : 0);
    err_count += (!b.ok() ? 1 : 0);
    err_count += (!c.ok() ? 1 : 0);
    err_count += (!d.ok() ? 1 : 0);
    err_count += (!e.ok() ? 1 : 0);
  }

  return AssertTrue(err_count > 0, "malformed payload fuzz harness executes");
}

}  // namespace

int main() {
  char state_dir_template[] = "/tmp/pqchat_serialize_state_XXXXXX";
  int state_fd = mkstemp(state_dir_template);
  if (state_fd < 0) {
    std::cerr << "FAIL: mkstemp for isolated state dir\n";
    return 1;
  }
  close(state_fd);
  unlink(state_dir_template);
  if (mkdir(state_dir_template, 0700) != 0) {
    std::cerr << "FAIL: mkdir for isolated state dir\n";
    return 1;
  }
  if (setenv("PQCHAT_STATE_DIR", state_dir_template, 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_DIR\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }
  if (setenv("PQCHAT_STATE_PASSPHRASE", "serialization-test-passphrase", 1) != 0) {
    std::cerr << "FAIL: setenv PQCHAT_STATE_PASSPHRASE\n";
    std::filesystem::remove_all(state_dir_template);
    return 1;
  }

  bool ok = true;
  ok &= TestCountAndLengthLimitRejections();
  ok &= TestPrekeyCountLimitRejection();
  ok &= TestMalformedFuzzHarness();
  unsetenv("PQCHAT_STATE_DIR");
  unsetenv("PQCHAT_STATE_PASSPHRASE");
  std::filesystem::remove_all(state_dir_template);
  if (!ok) {
    return 1;
  }
  std::cout << "PASS: serialization robustness test suite\n";
  return 0;
}
