#include "pqchat/client/client.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "pqchat/crypto/aead.h"
#include "pqchat/crypto/ed25519.h"
#include "pqchat/crypto/hash.h"
#include "pqchat/crypto/hkdf.h"
#include "pqchat/crypto/mldsa.h"
#include "pqchat/crypto/mlkem.h"
#include "pqchat/crypto/x25519.h"

namespace pqchat::client {
namespace {

constexpr const char* kLocalStatePayloadMagic = "pqchat_client_state_payload_v2";
constexpr const char* kLocalStateEncryptedMagic = "pqchat_client_state_encrypted_v1";
constexpr size_t kMaxStateFileBytes = 16 * 1024 * 1024;
constexpr size_t kStateEncryptionSaltBytes = 16;
constexpr size_t kStateEncryptionKeyBytes = 32;
constexpr int kStatePbkdf2Iterations = 210000;

class StateWriter {
 public:
  void U8(uint8_t value) {
    out_.push_back(value);
  }

  void U32(uint32_t value) {
    out_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out_.push_back(static_cast<uint8_t>(value & 0xFF));
  }

  void U64(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
      out_.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
  }

  void Bytes(const std::vector<uint8_t>& value) {
    U32(static_cast<uint32_t>(value.size()));
    out_.insert(out_.end(), value.begin(), value.end());
  }

  void Secure(const crypto::SecureBuffer& value) {
    Bytes(value.bytes());
  }

  void String(const std::string& value) {
    Bytes(std::vector<uint8_t>(value.begin(), value.end()));
  }

  std::vector<uint8_t> Take() {
    return std::move(out_);
  }

 private:
  std::vector<uint8_t> out_;
};

class StateReader {
 public:
  explicit StateReader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

  bool U8(uint8_t* out) {
    if (pos_ + 1 > bytes_.size()) {
      error_ = "unexpected EOF while reading u8";
      return false;
    }
    *out = bytes_[pos_++];
    return true;
  }

  bool U32(uint32_t* out) {
    if (pos_ + 4 > bytes_.size()) {
      error_ = "unexpected EOF while reading u32";
      return false;
    }
    *out = (static_cast<uint32_t>(bytes_[pos_]) << 24) |
           (static_cast<uint32_t>(bytes_[pos_ + 1]) << 16) |
           (static_cast<uint32_t>(bytes_[pos_ + 2]) << 8) |
           static_cast<uint32_t>(bytes_[pos_ + 3]);
    pos_ += 4;
    return true;
  }

  bool U64(uint64_t* out) {
    if (pos_ + 8 > bytes_.size()) {
      error_ = "unexpected EOF while reading u64";
      return false;
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
      value = (value << 8) | bytes_[pos_ + i];
    }
    pos_ += 8;
    *out = value;
    return true;
  }

  bool Bytes(std::vector<uint8_t>* out) {
    uint32_t len = 0;
    if (!U32(&len)) {
      return false;
    }
    if (pos_ + len > bytes_.size()) {
      error_ = "unexpected EOF while reading bytes";
      return false;
    }
    out->assign(bytes_.begin() + static_cast<long>(pos_),
                bytes_.begin() + static_cast<long>(pos_ + len));
    pos_ += len;
    return true;
  }

  bool Secure(crypto::SecureBuffer* out) {
    std::vector<uint8_t> bytes;
    if (!Bytes(&bytes)) {
      return false;
    }
    *out = crypto::SecureBuffer(std::move(bytes));
    return true;
  }

  bool String(std::string* out) {
    std::vector<uint8_t> bytes;
    if (!Bytes(&bytes)) {
      return false;
    }
    out->assign(bytes.begin(), bytes.end());
    return true;
  }

  bool LimitU32(uint32_t value, uint32_t max, const char* label) {
    if (value > max) {
      error_ = "decoded ";
      error_ += label;
      error_ += " exceeds limit";
      return false;
    }
    return true;
  }

  [[nodiscard]] bool Finished() const { return pos_ == bytes_.size(); }
  [[nodiscard]] const std::string& error() const { return error_; }

 private:
  const std::vector<uint8_t>& bytes_;
  size_t pos_ = 0;
  std::string error_;
};

Result<std::string> ReadStatePassphrase() {
  const char* passphrase = std::getenv("PQCHAT_STATE_PASSPHRASE");
  if (passphrase == nullptr || std::strlen(passphrase) == 0) {
    return Result<std::string>::Err(
        "PQCHAT_STATE_PASSPHRASE is required for encrypted local state");
  }
  return Result<std::string>::Ok(std::string(passphrase));
}

Result<std::vector<uint8_t>> DeriveStateEncryptionKey(
    const std::string& passphrase,
    const std::vector<uint8_t>& salt) {
  if (salt.size() != kStateEncryptionSaltBytes) {
    return Result<std::vector<uint8_t>>::Err("invalid state encryption salt");
  }
  std::vector<uint8_t> key(kStateEncryptionKeyBytes, 0);
  if (PKCS5_PBKDF2_HMAC(passphrase.data(),
                        static_cast<int>(passphrase.size()),
                        salt.data(),
                        static_cast<int>(salt.size()),
                        kStatePbkdf2Iterations,
                        EVP_sha256(),
                        static_cast<int>(key.size()),
                        key.data()) != 1) {
    return Result<std::vector<uint8_t>>::Err("PBKDF2 state key derivation failed");
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(key));
}

Result<std::vector<uint8_t>> EncryptStatePayload(
    const std::vector<uint8_t>& payload_plaintext) {
  auto passphrase = ReadStatePassphrase();
  if (!passphrase.ok()) {
    return Result<std::vector<uint8_t>>::Err(passphrase.error());
  }
  std::vector<uint8_t> salt(kStateEncryptionSaltBytes, 0);
  if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
    return Result<std::vector<uint8_t>>::Err("RAND_bytes failed");
  }
  auto key = DeriveStateEncryptionKey(passphrase.value(), salt);
  if (!key.ok()) {
    return Result<std::vector<uint8_t>>::Err(key.error());
  }

  auto nonce = crypto::NonceFromCounter(0);
  if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
    return Result<std::vector<uint8_t>>::Err("RAND_bytes failed");
  }
  auto ciphertext = crypto::AeadChaCha20Poly1305::Seal(
      key.value(),
      nonce,
      payload_plaintext,
      crypto::ToBytes(kLocalStateEncryptedMagic));
  if (!ciphertext.ok()) {
    return Result<std::vector<uint8_t>>::Err("state encryption failed: " + ciphertext.error());
  }

  StateWriter writer;
  writer.String(kLocalStateEncryptedMagic);
  writer.Bytes(salt);
  writer.Bytes(nonce);
  writer.Bytes(ciphertext.value());
  return Result<std::vector<uint8_t>>::Ok(writer.Take());
}

Result<std::vector<uint8_t>> UnwrapStatePayload(
    const std::vector<uint8_t>& file_bytes) {
  StateReader reader(file_bytes);
  std::string magic;
  if (!reader.String(&magic)) {
    return Result<std::vector<uint8_t>>::Err("decode local state wrapper failed: " +
                                             reader.error());
  }

  if (magic == kLocalStatePayloadMagic) {
    return Result<std::vector<uint8_t>>::Ok(file_bytes);
  }
  if (magic != kLocalStateEncryptedMagic) {
    return Result<std::vector<uint8_t>>::Err("unsupported local state format");
  }

  std::vector<uint8_t> salt;
  std::vector<uint8_t> nonce;
  std::vector<uint8_t> ciphertext;
  if (!reader.Bytes(&salt) || !reader.Bytes(&nonce) || !reader.Bytes(&ciphertext)) {
    return Result<std::vector<uint8_t>>::Err("decode local state wrapper failed: " +
                                             reader.error());
  }
  if (!reader.Finished()) {
    return Result<std::vector<uint8_t>>::Err(
        "decode local state wrapper failed: trailing bytes");
  }

  auto passphrase = ReadStatePassphrase();
  if (!passphrase.ok()) {
    return Result<std::vector<uint8_t>>::Err(passphrase.error());
  }
  auto key = DeriveStateEncryptionKey(passphrase.value(), salt);
  if (!key.ok()) {
    return Result<std::vector<uint8_t>>::Err(key.error());
  }
  auto plaintext = crypto::AeadChaCha20Poly1305::Open(
      key.value(),
      nonce,
      ciphertext,
      crypto::ToBytes(kLocalStateEncryptedMagic));
  if (!plaintext.ok()) {
    return Result<std::vector<uint8_t>>::Err("state decryption failed: " +
                                             plaintext.error());
  }
  return Result<std::vector<uint8_t>>::Ok(plaintext.take_value());
}

Result<void> FsyncDirectory(const std::string& dir) {
  int dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  if (dir_fd < 0) {
    return Result<void>::Err("failed opening state directory");
  }
  if (fsync(dir_fd) != 0) {
    close(dir_fd);
    return Result<void>::Err("failed syncing state directory");
  }
  if (close(dir_fd) != 0) {
    return Result<void>::Err("failed closing state directory");
  }
  return Result<void>::Ok();
}

Result<std::vector<uint8_t>> ReadAllFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    return Result<std::vector<uint8_t>>::Err("state file missing");
  }
  in.seekg(0, std::ios::end);
  std::streamoff size = in.tellg();
  if (size < 0) {
    return Result<std::vector<uint8_t>>::Err("failed to read state size");
  }
  if (static_cast<size_t>(size) > kMaxStateFileBytes) {
    return Result<std::vector<uint8_t>>::Err("state file too large");
  }
  in.seekg(0, std::ios::beg);
  std::vector<uint8_t> bytes(static_cast<size_t>(size));
  if (!bytes.empty()) {
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (in.gcount() != static_cast<std::streamsize>(bytes.size())) {
      return Result<std::vector<uint8_t>>::Err("state file read truncated");
    }
  }
  return Result<std::vector<uint8_t>>::Ok(std::move(bytes));
}

Result<void> WriteAllFileAtomic(const std::string& path, const std::vector<uint8_t>& bytes) {
  const size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || slash == 0) {
    return Result<void>::Err("invalid local state path");
  }
  const std::string dir = path.substr(0, slash);

  struct stat existing {};
  if (lstat(path.c_str(), &existing) == 0 && S_ISLNK(existing.st_mode)) {
    return Result<void>::Err("state file path must not be a symlink");
  }

  std::string tmp_template = dir + "/.pqchat_state_tmp_XXXXXX";
  std::vector<char> tmp_buf(tmp_template.begin(), tmp_template.end());
  tmp_buf.push_back('\0');
  int fd = mkstemp(tmp_buf.data());
  if (fd < 0) {
    return Result<void>::Err("failed to open state temp file");
  }
  const std::string tmp(tmp_buf.data());
  if (fchmod(fd, 0600) != 0) {
    close(fd);
    unlink(tmp.c_str());
    return Result<void>::Err("failed setting state temp file permissions");
  }
  size_t written = 0;
  while (written < bytes.size()) {
    ssize_t n = write(fd, bytes.data() + written, bytes.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      unlink(tmp.c_str());
      return Result<void>::Err("failed writing state file");
    }
    written += static_cast<size_t>(n);
  }
  if (fsync(fd) != 0) {
    close(fd);
    unlink(tmp.c_str());
    return Result<void>::Err("failed syncing state file");
  }
  if (close(fd) != 0) {
    unlink(tmp.c_str());
    return Result<void>::Err("failed closing state file");
  }
  if (rename(tmp.c_str(), path.c_str()) != 0) {
    unlink(tmp.c_str());
    return Result<void>::Err("failed committing state file");
  }
  auto dir_sync = FsyncDirectory(dir);
  if (!dir_sync.ok()) {
    return dir_sync;
  }
  return Result<void>::Ok();
}

std::string SanitizeForFile(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (unsigned char c : input) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '-' || c == '_' || c == '.') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('_');
    }
  }
  if (out.empty()) {
    out = "user";
  }
  return out;
}

Result<void> EnsureStateDir(const std::string& dir) {
  namespace fs = std::filesystem;

  struct stat st {};
  if (lstat(dir.c_str(), &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      return Result<void>::Err("state directory path must not be a symlink");
    }
    if (!S_ISDIR(st.st_mode)) {
      return Result<void>::Err("state path is not a directory");
    }
    if (chmod(dir.c_str(), 0700) != 0) {
      return Result<void>::Err("failed setting state directory permissions");
    }
    return Result<void>::Ok();
  }

  std::error_code ec;
  if (!fs::create_directories(dir, ec) && ec) {
    return Result<void>::Err("failed creating state directory");
  }
  if (chmod(dir.c_str(), 0700) != 0) {
    return Result<void>::Err("failed setting state directory permissions");
  }
  return Result<void>::Ok();
}

std::string HexEncode(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : bytes) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

std::vector<uint8_t> U64Bytes(uint64_t value) {
  std::vector<uint8_t> out(8);
  for (int i = 7; i >= 0; --i) {
    out[7 - i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
  }
  return out;
}

Result<std::vector<uint8_t>> DeriveKeyMaterial(const std::vector<uint8_t>& ikm,
                                               const std::vector<uint8_t>& salt,
                                               const std::string& label,
                                               const std::vector<uint8_t>& context,
                                               size_t out_len) {
  auto info = crypto::Concat({crypto::ToBytes(label), context});
  return crypto::HkdfSha256(ikm, salt, info, out_len);
}

Result<std::array<std::vector<uint8_t>, 3>> DeriveHandshakeKeys(
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& transcript_hash,
    bool initiator) {
  auto material_result =
      DeriveKeyMaterial(ikm,
                        {},
                        "pqchat_handshake_keys_v1",
                        transcript_hash,
                        96);
  if (!material_result.ok()) {
    return Result<std::array<std::vector<uint8_t>, 3>>::Err(material_result.error());
  }

  auto material = material_result.take_value();
  std::array<std::vector<uint8_t>, 3> out;
  out[0] = std::vector<uint8_t>(material.begin(), material.begin() + 32);  // root

  std::vector<uint8_t> c1(material.begin() + 32, material.begin() + 64);
  std::vector<uint8_t> c2(material.begin() + 64, material.begin() + 96);

  if (initiator) {
    out[1] = std::move(c1);  // send
    out[2] = std::move(c2);  // recv
  } else {
    out[1] = std::move(c2);  // send
    out[2] = std::move(c1);  // recv
  }

  return Result<std::array<std::vector<uint8_t>, 3>>::Ok(std::move(out));
}

Result<std::array<std::vector<uint8_t>, 2>> DeriveMessageKeyAndNextChain(
    const crypto::SecureBuffer& chain_key,
    uint64_t counter) {
  auto material = DeriveKeyMaterial(chain_key.bytes(),
                                    {},
                                    "pqchat_chain_step_v1",
                                    U64Bytes(counter),
                                    64);
  if (!material.ok()) {
    return Result<std::array<std::vector<uint8_t>, 2>>::Err(material.error());
  }

  auto bytes = material.take_value();
  std::array<std::vector<uint8_t>, 2> out;
  out[0] = std::vector<uint8_t>(bytes.begin(), bytes.begin() + 32);      // msg key
  out[1] = std::vector<uint8_t>(bytes.begin() + 32, bytes.begin() + 64); // next ck
  return Result<std::array<std::vector<uint8_t>, 2>>::Ok(std::move(out));
}

Result<std::array<std::vector<uint8_t>, 2>> DeriveRatchetRootAndChain(
    const std::vector<uint8_t>& dh,
    const crypto::SecureBuffer& root_key) {
  auto material = DeriveKeyMaterial(dh,
                                    root_key.bytes(),
                                    "pqchat_ratchet_step_v1",
                                    {},
                                    64);
  if (!material.ok()) {
    return Result<std::array<std::vector<uint8_t>, 2>>::Err(material.error());
  }

  auto bytes = material.take_value();
  std::array<std::vector<uint8_t>, 2> out;
  out[0] = std::vector<uint8_t>(bytes.begin(), bytes.begin() + 32);      // new chain
  out[1] = std::vector<uint8_t>(bytes.begin() + 32, bytes.begin() + 64); // new root
  return Result<std::array<std::vector<uint8_t>, 2>>::Ok(std::move(out));
}

Result<std::vector<uint8_t>> EncryptChainStep(crypto::SecureBuffer* chain_key,
                                              uint64_t counter,
                                              const std::vector<uint8_t>& nonce,
                                              const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& ad) {
  auto key_result = DeriveMessageKeyAndNextChain(*chain_key, counter);
  if (!key_result.ok()) {
    return Result<std::vector<uint8_t>>::Err(key_result.error());
  }
  auto keys = key_result.take_value();

  auto ciphertext = crypto::AeadChaCha20Poly1305::Seal(keys[0], nonce, plaintext, ad);
  if (!ciphertext.ok()) {
    return Result<std::vector<uint8_t>>::Err(ciphertext.error());
  }

  *chain_key = crypto::SecureBuffer(std::move(keys[1]));
  return Result<std::vector<uint8_t>>::Ok(ciphertext.take_value());
}

Result<std::vector<uint8_t>> DecryptChainStep(crypto::SecureBuffer* chain_key,
                                              uint64_t counter,
                                              const std::vector<uint8_t>& nonce,
                                              const std::vector<uint8_t>& ciphertext,
                                              const std::vector<uint8_t>& ad) {
  auto key_result = DeriveMessageKeyAndNextChain(*chain_key, counter);
  if (!key_result.ok()) {
    return Result<std::vector<uint8_t>>::Err(key_result.error());
  }
  auto keys = key_result.take_value();

  auto plaintext = crypto::AeadChaCha20Poly1305::Open(keys[0], nonce, ciphertext, ad);
  if (!plaintext.ok()) {
    return Result<std::vector<uint8_t>>::Err(plaintext.error());
  }

  *chain_key = crypto::SecureBuffer(std::move(keys[1]));
  return Result<std::vector<uint8_t>>::Ok(plaintext.take_value());
}

crypto::X25519KeyPair CloneX25519KeyPair(const crypto::X25519KeyPair& source) {
  crypto::X25519KeyPair out{
      crypto::SecureBuffer(std::vector<uint8_t>(source.private_key.bytes().begin(),
                                                source.private_key.bytes().end())),
      source.public_key};
  return out;
}

}  // namespace

Result<Client> Client::Create(std::string user_id) {
  Client client;
  client.user_id_ = std::move(user_id);
  client.local_state_path_ = DefaultLocalStatePath(client.user_id_);

  auto load_state = client.LoadLocalState();
  if (load_state.ok()) {
    auto refill = client.RefillOneTimePrekeyPools();
    if (!refill.ok()) {
      return Result<Client>::Err("state load prekey refill failed: " + refill.error());
    }
    auto persist = client.SaveLocalState();
    if (!persist.ok()) {
      return Result<Client>::Err("state persist failed: " + persist.error());
    }
    return Result<Client>::Ok(std::move(client));
  }
  if (load_state.error() != "state file missing") {
    return Result<Client>::Err("failed loading local state: " + load_state.error());
  }

  auto id_sign = crypto::Ed25519::GenerateKeyPair();
  if (!id_sign.ok()) {
    return Result<Client>::Err("identity Ed25519 keygen failed: " + id_sign.error());
  }
  client.identity_sign_key_ = id_sign.take_value();

  auto id_mldsa = crypto::MlDsa65::GenerateKeyPair();
  if (!id_mldsa.ok()) {
    return Result<Client>::Err("identity ML-DSA keygen failed: " + id_mldsa.error());
  }
  client.identity_mldsa_key_ = id_mldsa.take_value();

  auto id_dh = crypto::X25519::GenerateKeyPair();
  if (!id_dh.ok()) {
    return Result<Client>::Err("identity X25519 keygen failed: " + id_dh.error());
  }
  client.identity_dh_key_ = id_dh.take_value();

  auto spk_ec = crypto::X25519::GenerateKeyPair();
  if (!spk_ec.ok()) {
    return Result<Client>::Err("signed prekey EC keygen failed: " + spk_ec.error());
  }
  client.signed_prekey_ec_private_ = spk_ec.take_value();
  client.signed_prekey_ec_public_.id = 1;
  client.signed_prekey_ec_public_.public_key = client.signed_prekey_ec_private_.public_key;

  auto spk_ec_sig_input = protocol::BuildEcPrekeySignInput(
      client.signed_prekey_ec_public_.id,
      client.signed_prekey_ec_public_.public_key);
  auto spk_ec_sig =
      crypto::Ed25519::Sign(client.identity_sign_key_.private_key, spk_ec_sig_input);
  if (!spk_ec_sig.ok()) {
    return Result<Client>::Err("signed prekey EC signature failed: " + spk_ec_sig.error());
  }
  client.signed_prekey_ec_public_.signature_ed25519 = spk_ec_sig.take_value();

  auto spk_ec_sig_mldsa =
      crypto::MlDsa65::Sign(client.identity_mldsa_key_.private_key.get(), spk_ec_sig_input);
  if (!spk_ec_sig_mldsa.ok()) {
    return Result<Client>::Err("signed prekey EC ML-DSA signature failed: " +
                               spk_ec_sig_mldsa.error());
  }
  client.signed_prekey_ec_public_.signature_mldsa65 = spk_ec_sig_mldsa.take_value();

  auto spk_pq = crypto::MlKem768::GenerateKeyPair();
  if (!spk_pq.ok()) {
    return Result<Client>::Err("signed prekey PQ keygen failed: " + spk_pq.error());
  }
  client.signed_prekey_pq_private_ = spk_pq.take_value();
  client.signed_prekey_pq_public_.id = 1;
  client.signed_prekey_pq_public_.public_key = client.signed_prekey_pq_private_.public_key;

  auto spk_pq_sig_input = protocol::BuildPqPrekeySignInput(
      client.signed_prekey_pq_public_.id,
      client.signed_prekey_pq_public_.public_key);
  auto spk_pq_sig =
      crypto::Ed25519::Sign(client.identity_sign_key_.private_key, spk_pq_sig_input);
  if (!spk_pq_sig.ok()) {
    return Result<Client>::Err("signed prekey PQ signature failed: " + spk_pq_sig.error());
  }
  client.signed_prekey_pq_public_.signature_ed25519 = spk_pq_sig.take_value();

  auto spk_pq_sig_mldsa =
      crypto::MlDsa65::Sign(client.identity_mldsa_key_.private_key.get(), spk_pq_sig_input);
  if (!spk_pq_sig_mldsa.ok()) {
    return Result<Client>::Err("signed prekey PQ ML-DSA signature failed: " +
                               spk_pq_sig_mldsa.error());
  }
  client.signed_prekey_pq_public_.signature_mldsa65 = spk_pq_sig_mldsa.take_value();

  auto refill = client.RefillOneTimePrekeyPools();
  if (!refill.ok()) {
    return Result<Client>::Err("one-time prekey pool init failed: " + refill.error());
  }

  auto persist = client.SaveLocalState();
  if (!persist.ok()) {
    return Result<Client>::Err("state persist failed: " + persist.error());
  }

  return Result<Client>::Ok(std::move(client));
}

protocol::PrekeyBundle Client::BuildPrekeyBundle() const {
  protocol::PrekeyBundle bundle;
  bundle.user_id = user_id_;
  bundle.identity_sign_public_key = identity_sign_key_.public_key;
  bundle.identity_mldsa_public_key = identity_mldsa_key_.public_key;
  bundle.identity_dh_public_key = identity_dh_key_.public_key;
  bundle.signed_prekey_ec = signed_prekey_ec_public_;
  bundle.signed_prekey_pq = signed_prekey_pq_public_;
  bundle.version = protocol::kProtocolVersion;
  bundle.cipher_suite = protocol::kCipherSuite;

  bundle.one_time_ec.reserve(one_time_ec_pool_.size());
  for (const auto& one_time_ec : one_time_ec_pool_) {
    bundle.one_time_ec.push_back(one_time_ec.public_part);
  }

  bundle.one_time_pq.reserve(one_time_pq_pool_.size());
  for (const auto& one_time_pq : one_time_pq_pool_) {
    bundle.one_time_pq.push_back(one_time_pq.public_part);
  }

  auto bundle_sign_input = protocol::BuildBundleSignInput(bundle);
  auto bundle_sig_ed25519 =
      crypto::Ed25519::Sign(identity_sign_key_.private_key, bundle_sign_input);
  if (bundle_sig_ed25519.ok()) {
    bundle.bundle_signature_ed25519 = bundle_sig_ed25519.take_value();
  }

  auto bundle_sig_mldsa =
      crypto::MlDsa65::Sign(identity_mldsa_key_.private_key.get(), bundle_sign_input);
  if (bundle_sig_mldsa.ok()) {
    bundle.bundle_signature_mldsa65 = bundle_sig_mldsa.take_value();
  }

  return bundle;
}

Result<std::vector<uint8_t>> Client::SignTransportAuth(
    const std::vector<uint8_t>& message) const {
  return crypto::MlDsa65::Sign(identity_mldsa_key_.private_key.get(), message);
}

Result<std::string> Client::GetPeerSafetyNumber(const std::string& peer_user) const {
  auto it = trusted_peer_identities_.find(peer_user);
  if (it == trusted_peer_identities_.end()) {
    return Result<std::string>::Err("peer identity not known");
  }
  return ComputeSafetyNumber(peer_user,
                             it->second.sign_public_key,
                             it->second.mldsa_public_key,
                             it->second.dh_public_key);
}

Result<void> Client::VerifyPeerSafetyNumber(
    const std::string& peer_user,
    const std::string& expected_safety_number) {
  auto it = trusted_peer_identities_.find(peer_user);
  if (it == trusted_peer_identities_.end()) {
    return Result<void>::Err("peer identity not known");
  }
  auto computed = ComputeSafetyNumber(peer_user,
                                      it->second.sign_public_key,
                                      it->second.mldsa_public_key,
                                      it->second.dh_public_key);
  if (!computed.ok()) {
    return Result<void>::Err(computed.error());
  }
  if (computed.value() != expected_safety_number) {
    return Result<void>::Err("peer safety number mismatch");
  }
  it->second.verified = true;
  auto persist = SaveLocalState();
  if (!persist.ok()) {
    return Result<void>::Err("persist local state failed: " + persist.error());
  }
  return Result<void>::Ok();
}

Result<void> Client::PublishPrekeys(server::IServerApi* server) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }
  auto publish = server->PublishBundle(BuildPrekeyBundle());
  if (!publish.ok()) {
    return publish;
  }
  prekeys_dirty_ = false;
  auto save = SaveLocalState();
  if (!save.ok()) {
    return Result<void>::Err("persist local state failed: " + save.error());
  }
  return Result<void>::Ok();
}

Result<void> Client::InitiateSession(server::IServerApi* server,
                                     const std::string& peer_user,
                                     const std::string& initial_plaintext) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }

  auto bundle_result = server->AcquireBundleForSession(peer_user);
  if (!bundle_result.ok()) {
    return Result<void>::Err("failed to fetch peer bundle: " + bundle_result.error());
  }

  const auto& bundle = bundle_result.value();
  if (bundle.user_id != peer_user) {
    return Result<void>::Err("peer bundle user mismatch");
  }
  if (bundle.version != protocol::kProtocolVersion) {
    return Result<void>::Err("peer bundle uses unsupported protocol version");
  }
  if (bundle.cipher_suite != protocol::kCipherSuite) {
    return Result<void>::Err("peer bundle uses unsupported cipher suite");
  }
  auto verify = protocol::VerifyPrekeyBundleSignatures(bundle);
  if (!verify.ok()) {
    return Result<void>::Err("peer bundle verification failed: " + verify.error());
  }
  auto trust = VerifyOrRememberPeerIdentity(peer_user,
                                            bundle.identity_sign_public_key,
                                            bundle.identity_mldsa_public_key,
                                            bundle.identity_dh_public_key);
  if (!trust.ok()) {
    return trust;
  }

  auto session_id_result = NewSessionId();
  if (!session_id_result.ok()) {
    return Result<void>::Err(session_id_result.error());
  }
  const std::string session_id = session_id_result.take_value();

  if (bundle.one_time_ec.empty() || bundle.one_time_pq.empty()) {
    return Result<void>::Err("peer has no one-time prekeys available");
  }

  auto eph_result = crypto::X25519::GenerateKeyPair();
  if (!eph_result.ok()) {
    return Result<void>::Err("ephemeral keygen failed: " + eph_result.error());
  }
  auto eph = eph_result.take_value();
  const auto eph_public = eph.public_key;

  auto dh1 = crypto::X25519::SharedSecret(identity_dh_key_.private_key,
                                          bundle.signed_prekey_ec.public_key);
  if (!dh1.ok()) {
    return Result<void>::Err("dh1 failed: " + dh1.error());
  }

  auto dh2 = crypto::X25519::SharedSecret(eph.private_key,
                                          bundle.identity_dh_public_key);
  if (!dh2.ok()) {
    return Result<void>::Err("dh2 failed: " + dh2.error());
  }

  auto dh3 = crypto::X25519::SharedSecret(eph.private_key,
                                          bundle.signed_prekey_ec.public_key);
  if (!dh3.ok()) {
    return Result<void>::Err("dh3 failed: " + dh3.error());
  }

  std::optional<std::vector<uint8_t>> dh4;
  {
    const auto& one_time_ec = bundle.one_time_ec.front();
    auto dh4_result =
        crypto::X25519::SharedSecret(eph.private_key, one_time_ec.public_key);
    if (!dh4_result.ok()) {
      return Result<void>::Err("dh4 failed: " + dh4_result.error());
    }
    dh4 = dh4_result.take_value();
  }

  auto kem_spk = crypto::MlKem768::Encapsulate(bundle.signed_prekey_pq.public_key);
  if (!kem_spk.ok()) {
    return Result<void>::Err("KEM encaps to signed prekey failed: " + kem_spk.error());
  }

  std::optional<crypto::MlKemEncapResult> kem_opk;
  {
    const auto& one_time_pq = bundle.one_time_pq.front();
    auto kem_opk_result = crypto::MlKem768::Encapsulate(one_time_pq.public_key);
    if (!kem_opk_result.ok()) {
      return Result<void>::Err("KEM encaps to one-time prekey failed: " +
                               kem_opk_result.error());
    }
    kem_opk = kem_opk_result.take_value();
  }

  protocol::InitialTranscriptFields transcript_fields;
  transcript_fields.session_id = session_id;
  transcript_fields.from_user = user_id_;
  transcript_fields.to_user = peer_user;
  transcript_fields.version = protocol::kProtocolVersion;
  transcript_fields.cipher_suite = protocol::kCipherSuite;
  transcript_fields.initiator_identity_sign_public_key = identity_sign_key_.public_key;
  transcript_fields.initiator_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  transcript_fields.initiator_identity_dh_public_key = identity_dh_key_.public_key;
  transcript_fields.responder_identity_sign_public_key = bundle.identity_sign_public_key;
  transcript_fields.responder_identity_mldsa_public_key = bundle.identity_mldsa_public_key;
  transcript_fields.responder_identity_dh_public_key = bundle.identity_dh_public_key;
  transcript_fields.initiator_ephemeral_ec_public_key = eph_public;
  transcript_fields.selected_prekeys.signed_prekey_ec_id = bundle.signed_prekey_ec.id;
  transcript_fields.selected_prekeys.signed_prekey_pq_id = bundle.signed_prekey_pq.id;

  transcript_fields.selected_prekeys.one_time_ec_id = bundle.one_time_ec.front().id;
  transcript_fields.selected_prekeys.one_time_pq_id = bundle.one_time_pq.front().id;

  transcript_fields.kem_ciphertext_signed_pq = kem_spk.value().ciphertext;
  transcript_fields.kem_ciphertext_one_time_pq = kem_opk->ciphertext;

  auto transcript_hash = protocol::ComputeInitialTranscriptHash(transcript_fields);
  if (!transcript_hash.ok()) {
    return Result<void>::Err("transcript hash failed: " + transcript_hash.error());
  }

  auto handshake_sig =
      crypto::Ed25519::Sign(identity_sign_key_.private_key, transcript_hash.value());
  if (!handshake_sig.ok()) {
    return Result<void>::Err("handshake ed25519 signature failed: " + handshake_sig.error());
  }

  auto handshake_sig_mldsa =
      crypto::MlDsa65::Sign(identity_mldsa_key_.private_key.get(), transcript_hash.value());
  if (!handshake_sig_mldsa.ok()) {
    return Result<void>::Err("handshake mldsa signature failed: " +
                             handshake_sig_mldsa.error());
  }

  std::vector<std::vector<uint8_t>> ikm_parts = {
      dh1.value(), dh2.value(), dh3.value(), kem_spk.value().shared_secret};
  if (dh4.has_value()) {
    ikm_parts.push_back(*dh4);
  }
  if (kem_opk.has_value()) {
    ikm_parts.push_back(kem_opk->shared_secret);
  }

  auto handshake_keys =
      DeriveHandshakeKeys(crypto::Concat(ikm_parts), transcript_hash.value(), true);
  if (!handshake_keys.ok()) {
    return Result<void>::Err("handshake key schedule failed: " + handshake_keys.error());
  }

  SessionState state;
  state.session_id = session_id;
  state.peer_user = peer_user;
  state.is_initiator = true;
  state.root_key = crypto::SecureBuffer(std::move(handshake_keys.value()[0]));
  state.send_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[1]));
  state.recv_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[2]));
  state.local_ratchet_key = std::move(eph);
  state.remote_ratchet_public = bundle.signed_prekey_ec.public_key;

  protocol::InitialMessage initial_message;
  initial_message.session_id = state.session_id;
  initial_message.from_user = user_id_;
  initial_message.to_user = peer_user;
  initial_message.version = protocol::kProtocolVersion;
  initial_message.cipher_suite = protocol::kCipherSuite;
  initial_message.initiator_identity_sign_public_key = identity_sign_key_.public_key;
  initial_message.initiator_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  initial_message.initiator_identity_dh_public_key = identity_dh_key_.public_key;
  initial_message.initiator_ephemeral_ec_public_key = eph_public;
  initial_message.selected_prekeys = transcript_fields.selected_prekeys;
  initial_message.kem_ciphertext_signed_pq = kem_spk.value().ciphertext;
  initial_message.kem_ciphertext_one_time_pq = kem_opk->ciphertext;
  initial_message.transcript_hash = transcript_hash.value();
  initial_message.handshake_signature_ed25519 = handshake_sig.take_value();
  initial_message.handshake_signature_mldsa65 = handshake_sig_mldsa.take_value();

  initial_message.initial_nonce = crypto::NonceFromCounter(state.send_counter);
  auto encrypted_initial = EncryptChainStep(&state.send_chain_key,
                                            state.send_counter,
                                            initial_message.initial_nonce,
                                            crypto::ToBytes(initial_plaintext),
                                            transcript_hash.value());
  if (!encrypted_initial.ok()) {
    return Result<void>::Err("encrypt initial payload failed: " + encrypted_initial.error());
  }
  initial_message.initial_ciphertext = encrypted_initial.take_value();
  state.send_counter++;

  auto replay_guard = RememberInitialReplayGuards(state.session_id, transcript_hash.value());
  if (!replay_guard.ok()) {
    return replay_guard;
  }

  sessions_by_peer_[peer_user] = std::move(state);

  auto enqueue = server->EnqueueEnvelope(peer_user,
                                         protocol::Envelope::FromInitial(std::move(initial_message)));
  if (!enqueue.ok()) {
    return enqueue;
  }
  auto save = SaveLocalState();
  if (!save.ok()) {
    return Result<void>::Err("persist local state failed: " + save.error());
  }
  return Result<void>::Ok();
}

Result<void> Client::SendMessage(server::IServerApi* server,
                                 const std::string& peer_user,
                                 const std::string& plaintext) {
  if (server == nullptr) {
    return Result<void>::Err("server is null");
  }

  auto session_it = sessions_by_peer_.find(peer_user);
  if (session_it == sessions_by_peer_.end()) {
    return Result<void>::Err("no active session with peer");
  }
  auto& session = session_it->second;

  protocol::ChatMessage message;
  message.session_id = session.session_id;
  message.from_user = user_id_;
  message.to_user = peer_user;

  if (session.send_counter > 0 && session.send_counter % kRatchetInterval == 0) {
    auto new_ratchet_result = crypto::X25519::GenerateKeyPair();
    if (!new_ratchet_result.ok()) {
      return Result<void>::Err("ratchet keygen failed: " + new_ratchet_result.error());
    }

    auto dh = crypto::X25519::SharedSecret(new_ratchet_result.value().private_key,
                                           session.remote_ratchet_public);
    if (!dh.ok()) {
      return Result<void>::Err("ratchet DH failed: " + dh.error());
    }

    auto mixed = DeriveRatchetRootAndChain(dh.value(), session.root_key);
    if (!mixed.ok()) {
      return Result<void>::Err("ratchet KDF failed: " + mixed.error());
    }

    session.local_ratchet_key = new_ratchet_result.take_value();
    session.send_chain_key = crypto::SecureBuffer(std::move(mixed.value()[0]));
    session.root_key = crypto::SecureBuffer(std::move(mixed.value()[1]));

    message.header.sender_ratchet_public_key = session.local_ratchet_key.public_key;
    message.header.previous_chain_length = session.previous_send_chain_length;
    session.previous_send_chain_length = session.send_counter;
    session.send_counter = 0;
    message.header.flags |= 0x1;
  }

  message.header.message_number = session.send_counter;
  message.nonce = crypto::NonceFromCounter(session.send_counter);

  auto ad = protocol::BuildChatAssociatedData(message);
  if (!ad.ok()) {
    return Result<void>::Err("chat AD failed: " + ad.error());
  }

  auto ciphertext = EncryptChainStep(&session.send_chain_key,
                                     session.send_counter,
                                     message.nonce,
                                     crypto::ToBytes(plaintext),
                                     ad.value());
  if (!ciphertext.ok()) {
    return Result<void>::Err("message encryption failed: " + ciphertext.error());
  }
  message.ciphertext = ciphertext.take_value();
  session.send_counter++;

  auto enqueue = server->EnqueueEnvelope(peer_user, protocol::Envelope::FromChat(std::move(message)));
  if (!enqueue.ok()) {
    return enqueue;
  }
  auto save = SaveLocalState();
  if (!save.ok()) {
    return Result<void>::Err("persist local state failed: " + save.error());
  }
  return Result<void>::Ok();
}

Result<std::vector<std::string>> Client::ProcessInbox(server::IServerApi* server) {
  if (server == nullptr) {
    return Result<std::vector<std::string>>::Err("server is null");
  }

  std::vector<std::string> plaintexts;
  std::string first_error;
  std::optional<uint64_t> ack_to_send = pending_inbox_ack_up_to_id_;

  for (size_t pass = 0; pass < kMaxInboxDrainPasses; ++pass) {
    auto envelopes_result = server->DrainInbox(user_id_, ack_to_send);
    if (!envelopes_result.ok()) {
      if (ack_to_send.has_value()) {
        pending_inbox_ack_up_to_id_ = ack_to_send;
      }
      if (plaintexts.empty() && first_error.empty()) {
        return Result<std::vector<std::string>>::Err("drain inbox failed: " +
                                                     envelopes_result.error());
      }
      if (first_error.empty()) {
        first_error = "drain inbox failed: " + envelopes_result.error();
      }
      break;
    }
    ack_to_send.reset();
    pending_inbox_ack_up_to_id_.reset();

    auto inbox_envelopes = envelopes_result.take_value();
    if (inbox_envelopes.empty()) {
      pending_inbox_ack_up_to_id_.reset();
      break;
    }

    std::optional<uint64_t> max_ackable_inbox_id;
    bool saw_processing_error = false;
    for (const auto& inbox_item : inbox_envelopes) {
      Result<void> status = Result<void>::Ok();
      const auto& envelope = inbox_item.envelope;
      if (envelope.type == protocol::EnvelopeType::kInitial && envelope.initial.has_value()) {
        status = HandleInitialMessage(*envelope.initial, &plaintexts);
      } else if (envelope.type == protocol::EnvelopeType::kChat &&
                 envelope.chat.has_value()) {
        status = HandleChatMessage(*envelope.chat, &plaintexts);
      } else {
        status = Result<void>::Err("invalid envelope");
      }

      if (!status.ok() && first_error.empty()) {
        first_error = status.error();
      }
      if (!status.ok()) {
        saw_processing_error = true;
        break;
      }
      max_ackable_inbox_id = inbox_item.inbox_id;
    }

    if (max_ackable_inbox_id.has_value()) {
      ack_to_send = max_ackable_inbox_id;
      pending_inbox_ack_up_to_id_ = max_ackable_inbox_id;
    }
    if (saw_processing_error) {
      break;
    }
  }

  if (prekeys_dirty_) {
    auto refill = RefillOneTimePrekeyPools();
    if (!refill.ok() && first_error.empty()) {
      first_error = "prekey pool refill failed: " + refill.error();
    } else {
      auto publish = PublishPrekeys(server);
      if (!publish.ok() && first_error.empty()) {
        first_error = "prekey republish failed: " + publish.error();
      } else if (publish.ok()) {
        prekeys_dirty_ = false;
      }
    }
  }

  if (plaintexts.empty() && !first_error.empty()) {
    return Result<std::vector<std::string>>::Err(first_error);
  }

  auto save = SaveLocalState();
  if (!save.ok()) {
    if (plaintexts.empty() && first_error.empty()) {
      return Result<std::vector<std::string>>::Err(
          "persist local state failed: " + save.error());
    }
    if (first_error.empty()) {
      first_error = "persist local state failed: " + save.error();
    }
  }
  if (plaintexts.empty() && !first_error.empty()) {
    return Result<std::vector<std::string>>::Err(first_error);
  }

  return Result<std::vector<std::string>>::Ok(std::move(plaintexts));
}

Result<void> Client::HandleInitialMessage(const protocol::InitialMessage& message,
                                          std::vector<std::string>* plaintext_out) {
  if (message.to_user != user_id_) {
    return Result<void>::Err("initial message recipient mismatch");
  }
  if (message.version != protocol::kProtocolVersion) {
    return Result<void>::Err("initial message uses unsupported protocol version");
  }
  if (message.cipher_suite != protocol::kCipherSuite) {
    return Result<void>::Err("initial message uses unsupported cipher suite");
  }
  if (!message.selected_prekeys.one_time_ec_id.has_value() ||
      !message.selected_prekeys.one_time_pq_id.has_value() ||
      !message.kem_ciphertext_one_time_pq.has_value()) {
    return Result<void>::Err("initial message must include one-time EC and PQ prekeys");
  }
  if (HasSeenInitialReplayGuard(message.session_id, message.transcript_hash)) {
    return Result<void>::Err("duplicate initial handshake rejected");
  }

  if (message.selected_prekeys.signed_prekey_ec_id != signed_prekey_ec_public_.id ||
      message.selected_prekeys.signed_prekey_pq_id != signed_prekey_pq_public_.id) {
    return Result<void>::Err("initial message selected unknown signed prekey id");
  }

  protocol::InitialTranscriptFields fields;
  fields.session_id = message.session_id;
  fields.from_user = message.from_user;
  fields.to_user = message.to_user;
  fields.version = message.version;
  fields.cipher_suite = message.cipher_suite;
  fields.initiator_identity_sign_public_key = message.initiator_identity_sign_public_key;
  fields.initiator_identity_mldsa_public_key = message.initiator_identity_mldsa_public_key;
  fields.initiator_identity_dh_public_key = message.initiator_identity_dh_public_key;
  fields.responder_identity_sign_public_key = identity_sign_key_.public_key;
  fields.responder_identity_mldsa_public_key = identity_mldsa_key_.public_key;
  fields.responder_identity_dh_public_key = identity_dh_key_.public_key;
  fields.initiator_ephemeral_ec_public_key = message.initiator_ephemeral_ec_public_key;
  fields.selected_prekeys = message.selected_prekeys;
  fields.kem_ciphertext_signed_pq = message.kem_ciphertext_signed_pq;
  fields.kem_ciphertext_one_time_pq = message.kem_ciphertext_one_time_pq;

  auto transcript_hash = protocol::ComputeInitialTranscriptHash(fields);
  if (!transcript_hash.ok()) {
    return Result<void>::Err("transcript hash failed: " + transcript_hash.error());
  }
  if (transcript_hash.value() != message.transcript_hash) {
    return Result<void>::Err("transcript hash mismatch");
  }

  auto sig_verify = crypto::Ed25519::Verify(message.initiator_identity_sign_public_key,
                                            message.transcript_hash,
                                            message.handshake_signature_ed25519);
  if (!sig_verify.ok()) {
    return Result<void>::Err("handshake ed25519 signature invalid: " + sig_verify.error());
  }

  auto sig_verify_mldsa =
      crypto::MlDsa65::Verify(message.initiator_identity_mldsa_public_key,
                              message.transcript_hash,
                              message.handshake_signature_mldsa65);
  if (!sig_verify_mldsa.ok()) {
    return Result<void>::Err("handshake mldsa signature invalid: " +
                             sig_verify_mldsa.error());
  }

  auto trust = VerifyOrRememberPeerIdentity(message.from_user,
                                            message.initiator_identity_sign_public_key,
                                            message.initiator_identity_mldsa_public_key,
                                            message.initiator_identity_dh_public_key);
  if (!trust.ok()) {
    return trust;
  }

  auto dh1 = crypto::X25519::SharedSecret(signed_prekey_ec_private_.private_key,
                                          message.initiator_identity_dh_public_key);
  if (!dh1.ok()) {
    return Result<void>::Err("dh1 failed: " + dh1.error());
  }

  auto dh2 = crypto::X25519::SharedSecret(identity_dh_key_.private_key,
                                          message.initiator_ephemeral_ec_public_key);
  if (!dh2.ok()) {
    return Result<void>::Err("dh2 failed: " + dh2.error());
  }

  auto dh3 = crypto::X25519::SharedSecret(signed_prekey_ec_private_.private_key,
                                          message.initiator_ephemeral_ec_public_key);
  if (!dh3.ok()) {
    return Result<void>::Err("dh3 failed: " + dh3.error());
  }

  std::optional<std::vector<uint8_t>> dh4;
  auto one_time_ec_it =
      std::find_if(one_time_ec_pool_.begin(),
                   one_time_ec_pool_.end(),
                   [&](const OneTimeEc& key) {
                     return key.public_part.id ==
                            *message.selected_prekeys.one_time_ec_id;
                   });
  if (one_time_ec_it == one_time_ec_pool_.end()) {
    return Result<void>::Err("one-time EC key id unavailable");
  }
  {
    auto dh4_result =
        crypto::X25519::SharedSecret(one_time_ec_it->private_part.private_key,
                                     message.initiator_ephemeral_ec_public_key);
    if (!dh4_result.ok()) {
      return Result<void>::Err("dh4 failed: " + dh4_result.error());
    }
    dh4 = dh4_result.take_value();
  }

  auto ss_spk_pq = crypto::MlKem768::Decapsulate(signed_prekey_pq_private_.private_key.get(),
                                                 message.kem_ciphertext_signed_pq);
  if (!ss_spk_pq.ok()) {
    return Result<void>::Err("decapsulate signed PQ prekey failed: " + ss_spk_pq.error());
  }

  std::optional<std::vector<uint8_t>> ss_opk_pq;
  auto one_time_pq_it =
      std::find_if(one_time_pq_pool_.begin(),
                   one_time_pq_pool_.end(),
                   [&](const OneTimePq& key) {
                     return key.public_part.id ==
                            *message.selected_prekeys.one_time_pq_id;
                   });
  if (one_time_pq_it == one_time_pq_pool_.end()) {
    return Result<void>::Err("one-time PQ key id unavailable");
  }
  {

    auto ss_opk_pq_result = crypto::MlKem768::Decapsulate(
        one_time_pq_it->private_part.private_key.get(),
        *message.kem_ciphertext_one_time_pq);
    if (!ss_opk_pq_result.ok()) {
      return Result<void>::Err("decapsulate one-time PQ prekey failed: " +
                               ss_opk_pq_result.error());
    }
    ss_opk_pq = ss_opk_pq_result.take_value();
  }

  std::vector<std::vector<uint8_t>> ikm_parts = {
      dh1.value(), dh2.value(), dh3.value(), ss_spk_pq.value()};
  if (dh4.has_value()) {
    ikm_parts.push_back(*dh4);
  }
  if (ss_opk_pq.has_value()) {
    ikm_parts.push_back(*ss_opk_pq);
  }

  auto handshake_keys =
      DeriveHandshakeKeys(crypto::Concat(ikm_parts), message.transcript_hash, false);
  if (!handshake_keys.ok()) {
    return Result<void>::Err("handshake key schedule failed: " + handshake_keys.error());
  }

  SessionState state;
  state.session_id = message.session_id;
  state.peer_user = message.from_user;
  state.is_initiator = false;
  state.root_key = crypto::SecureBuffer(std::move(handshake_keys.value()[0]));
  state.send_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[1]));
  state.recv_chain_key = crypto::SecureBuffer(std::move(handshake_keys.value()[2]));
  state.local_ratchet_key = CloneX25519KeyPair(signed_prekey_ec_private_);
  state.remote_ratchet_public = message.initiator_ephemeral_ec_public_key;

  auto plaintext = DecryptChainStep(&state.recv_chain_key,
                                    state.recv_counter,
                                    message.initial_nonce,
                                    message.initial_ciphertext,
                                    message.transcript_hash);
  if (!plaintext.ok()) {
    return Result<void>::Err("initial payload decrypt failed: " + plaintext.error());
  }

  auto replay_guard = RememberInitialReplayGuards(message.session_id, message.transcript_hash);
  if (!replay_guard.ok()) {
    return replay_guard;
  }

  one_time_ec_pool_.erase(one_time_ec_it);
  one_time_pq_pool_.erase(one_time_pq_it);
  prekeys_dirty_ = true;

  state.recv_counter++;
  sessions_by_peer_[message.from_user] = std::move(state);

  plaintext_out->push_back(
      std::string(plaintext.value().begin(), plaintext.value().end()));
  return Result<void>::Ok();
}

Result<void> Client::RefillOneTimePrekeyPools() {
  while (one_time_ec_pool_.size() < kOneTimePrekeyPoolTarget) {
    auto opk_ec_private = crypto::X25519::GenerateKeyPair();
    if (!opk_ec_private.ok()) {
      return Result<void>::Err("one-time EC keygen failed: " + opk_ec_private.error());
    }

    auto id_result = GenerateUniqueOneTimePrekeyId();
    if (!id_result.ok()) {
      return Result<void>::Err(id_result.error());
    }

    OneTimeEc one_time_ec;
    one_time_ec.public_part.id = id_result.take_value();
    one_time_ec.public_part.public_key = opk_ec_private.value().public_key;
    one_time_ec.private_part = opk_ec_private.take_value();
    one_time_ec_pool_.push_back(std::move(one_time_ec));
    prekeys_dirty_ = true;
  }

  while (one_time_pq_pool_.size() < kOneTimePrekeyPoolTarget) {
    auto opk_pq_private = crypto::MlKem768::GenerateKeyPair();
    if (!opk_pq_private.ok()) {
      return Result<void>::Err("one-time PQ keygen failed: " + opk_pq_private.error());
    }

    auto id_result = GenerateUniqueOneTimePrekeyId();
    if (!id_result.ok()) {
      return Result<void>::Err(id_result.error());
    }

    OneTimePq one_time_pq;
    one_time_pq.public_part.id = id_result.take_value();
    one_time_pq.public_part.public_key = opk_pq_private.value().public_key;
    one_time_pq.private_part = opk_pq_private.take_value();
    one_time_pq_pool_.push_back(std::move(one_time_pq));
    prekeys_dirty_ = true;
  }

  return Result<void>::Ok();
}

Result<uint32_t> Client::GenerateUniqueOneTimePrekeyId() const {
  auto id_in_use = [&](uint32_t candidate) {
    for (const auto& key : one_time_ec_pool_) {
      if (key.public_part.id == candidate) {
        return true;
      }
    }
    for (const auto& key : one_time_pq_pool_) {
      if (key.public_part.id == candidate) {
        return true;
      }
    }
    return false;
  };

  for (size_t attempt = 0; attempt < 32; ++attempt) {
    std::array<uint8_t, 4> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
      return Result<uint32_t>::Err("RAND_bytes failed");
    }
    uint32_t candidate = (static_cast<uint32_t>(random[0]) << 24) |
                         (static_cast<uint32_t>(random[1]) << 16) |
                         (static_cast<uint32_t>(random[2]) << 8) |
                         static_cast<uint32_t>(random[3]);
    if (candidate == 0 || id_in_use(candidate)) {
      continue;
    }
    return Result<uint32_t>::Ok(candidate);
  }

  return Result<uint32_t>::Err("failed to generate unique one-time prekey id");
}

std::string Client::DefaultLocalStatePath(const std::string& user_id) {
  const char* env_dir = std::getenv("PQCHAT_STATE_DIR");
  std::string dir;
  if (env_dir != nullptr && std::strlen(env_dir) > 0) {
    dir = env_dir;
  } else {
    const char* xdg_state_home = std::getenv("XDG_STATE_HOME");
    const char* home = std::getenv("HOME");
    if (xdg_state_home != nullptr && std::strlen(xdg_state_home) > 0) {
      dir = std::string(xdg_state_home) + "/pqchat";
    } else if (home != nullptr && std::strlen(home) > 0) {
      dir = std::string(home) + "/.local/state/pqchat";
    } else {
      dir = "/tmp/pqchat_state";
    }
  }
  return dir + "/" + SanitizeForFile(user_id) + ".bin";
}

Result<void> Client::SaveLocalState() const {
  const size_t slash = local_state_path_.find_last_of('/');
  if (slash == std::string::npos || slash == 0) {
    return Result<void>::Err("invalid local state path");
  }
  auto ensure_dir = EnsureStateDir(local_state_path_.substr(0, slash));
  if (!ensure_dir.ok()) {
    return ensure_dir;
  }

  StateWriter writer;
  writer.String(kLocalStatePayloadMagic);
  writer.String(user_id_);
  writer.String(protocol::kProtocolVersion);

  writer.Secure(identity_sign_key_.private_key);
  writer.Bytes(identity_sign_key_.public_key);

  auto identity_mldsa_private =
      crypto::MlDsa65::ExportPrivateKey(identity_mldsa_key_.private_key.get());
  if (!identity_mldsa_private.ok()) {
    return Result<void>::Err("export identity mldsa private key failed: " +
                             identity_mldsa_private.error());
  }
  writer.Bytes(identity_mldsa_private.value());
  writer.Bytes(identity_mldsa_key_.public_key);

  writer.Secure(identity_dh_key_.private_key);
  writer.Bytes(identity_dh_key_.public_key);

  writer.U32(signed_prekey_ec_public_.id);
  writer.Bytes(signed_prekey_ec_public_.public_key);
  writer.Bytes(signed_prekey_ec_public_.signature_ed25519);
  writer.Bytes(signed_prekey_ec_public_.signature_mldsa65);
  writer.Secure(signed_prekey_ec_private_.private_key);

  writer.U32(signed_prekey_pq_public_.id);
  writer.Bytes(signed_prekey_pq_public_.public_key);
  writer.Bytes(signed_prekey_pq_public_.signature_ed25519);
  writer.Bytes(signed_prekey_pq_public_.signature_mldsa65);
  auto signed_prekey_pq_private =
      crypto::MlKem768::ExportPrivateKey(signed_prekey_pq_private_.private_key.get());
  if (!signed_prekey_pq_private.ok()) {
    return Result<void>::Err("export signed prekey pq private key failed: " +
                             signed_prekey_pq_private.error());
  }
  writer.Bytes(signed_prekey_pq_private.value());

  writer.U32(static_cast<uint32_t>(one_time_ec_pool_.size()));
  for (const auto& key : one_time_ec_pool_) {
    writer.U32(key.public_part.id);
    writer.Bytes(key.public_part.public_key);
    writer.Secure(key.private_part.private_key);
  }

  writer.U32(static_cast<uint32_t>(one_time_pq_pool_.size()));
  for (const auto& key : one_time_pq_pool_) {
    writer.U32(key.public_part.id);
    writer.Bytes(key.public_part.public_key);
    auto priv = crypto::MlKem768::ExportPrivateKey(key.private_part.private_key.get());
    if (!priv.ok()) {
      return Result<void>::Err("export one-time pq private key failed: " + priv.error());
    }
    writer.Bytes(priv.value());
  }

  writer.U8(prekeys_dirty_ ? 1 : 0);
  writer.U8(pending_inbox_ack_up_to_id_.has_value() ? 1 : 0);
  if (pending_inbox_ack_up_to_id_.has_value()) {
    writer.U64(*pending_inbox_ack_up_to_id_);
  }

  if (trusted_peer_identities_.size() > kMaxPersistedPeers) {
    return Result<void>::Err("too many trusted peer identities to persist");
  }
  writer.U32(static_cast<uint32_t>(trusted_peer_identities_.size()));
  for (const auto& [peer_user, peer] : trusted_peer_identities_) {
    writer.String(peer_user);
    writer.Bytes(peer.sign_public_key);
    writer.Bytes(peer.mldsa_public_key);
    writer.Bytes(peer.dh_public_key);
    writer.U8(peer.verified ? 1 : 0);
  }

  if (sessions_by_peer_.size() > kMaxPersistedSessions) {
    return Result<void>::Err("too many sessions to persist");
  }
  writer.U32(static_cast<uint32_t>(sessions_by_peer_.size()));
  for (const auto& [peer_user, session] : sessions_by_peer_) {
    writer.String(peer_user);
    writer.String(session.session_id);
    writer.String(session.peer_user);
    writer.U8(session.is_initiator ? 1 : 0);
    writer.Secure(session.root_key);
    writer.Secure(session.send_chain_key);
    writer.Secure(session.recv_chain_key);
    writer.U64(session.send_counter);
    writer.U64(session.recv_counter);
    writer.U64(session.previous_send_chain_length);
    writer.Secure(session.local_ratchet_key.private_key);
    writer.Bytes(session.local_ratchet_key.public_key);
    writer.Bytes(session.remote_ratchet_public);
  }

  writer.U32(static_cast<uint32_t>(seen_initial_session_order_.size()));
  for (const auto& session_id : seen_initial_session_order_) {
    writer.String(session_id);
  }
  writer.U32(static_cast<uint32_t>(seen_initial_transcript_order_.size()));
  for (const auto& transcript_hash : seen_initial_transcript_order_) {
    writer.String(transcript_hash);
  }

  auto wrapped = EncryptStatePayload(writer.Take());
  if (!wrapped.ok()) {
    return Result<void>::Err(wrapped.error());
  }
  return WriteAllFileAtomic(local_state_path_, wrapped.value());
}

Result<void> Client::LoadLocalState() {
  auto bytes_result = ReadAllFile(local_state_path_);
  if (!bytes_result.ok()) {
    return Result<void>::Err(bytes_result.error());
  }
  auto payload_result = UnwrapStatePayload(bytes_result.value());
  if (!payload_result.ok()) {
    return Result<void>::Err(payload_result.error());
  }
  StateReader reader(payload_result.value());

  std::string magic;
  std::string stored_user;
  std::string stored_version;
  if (!reader.String(&magic) || !reader.String(&stored_user) || !reader.String(&stored_version)) {
    return Result<void>::Err("decode local state header failed: " + reader.error());
  }
  if (magic != kLocalStatePayloadMagic) {
    return Result<void>::Err("unsupported local state format");
  }
  if (stored_user != user_id_) {
    return Result<void>::Err("local state user mismatch");
  }
  if (stored_version != protocol::kProtocolVersion) {
    return Result<void>::Err("local state protocol version mismatch");
  }

  crypto::SecureBuffer id_sign_private;
  std::vector<uint8_t> id_sign_public;
  if (!reader.Secure(&id_sign_private) || !reader.Bytes(&id_sign_public)) {
    return Result<void>::Err("decode local state identity sign key failed: " +
                             reader.error());
  }
  identity_sign_key_ = crypto::Ed25519KeyPair{std::move(id_sign_private),
                                               std::move(id_sign_public)};

  std::vector<uint8_t> id_mldsa_private;
  std::vector<uint8_t> id_mldsa_public;
  if (!reader.Bytes(&id_mldsa_private) || !reader.Bytes(&id_mldsa_public)) {
    return Result<void>::Err("decode local state identity mldsa key failed: " +
                             reader.error());
  }
  auto id_mldsa = crypto::MlDsa65::FromPrivateKey(id_mldsa_private, id_mldsa_public);
  if (!id_mldsa.ok()) {
    return Result<void>::Err("restore identity mldsa key failed: " + id_mldsa.error());
  }
  identity_mldsa_key_ = id_mldsa.take_value();

  crypto::SecureBuffer id_dh_private;
  std::vector<uint8_t> id_dh_public;
  if (!reader.Secure(&id_dh_private) || !reader.Bytes(&id_dh_public)) {
    return Result<void>::Err("decode local state identity dh key failed: " +
                             reader.error());
  }
  identity_dh_key_ = crypto::X25519KeyPair{std::move(id_dh_private), std::move(id_dh_public)};

  if (!reader.U32(&signed_prekey_ec_public_.id) ||
      !reader.Bytes(&signed_prekey_ec_public_.public_key) ||
      !reader.Bytes(&signed_prekey_ec_public_.signature_ed25519) ||
      !reader.Bytes(&signed_prekey_ec_public_.signature_mldsa65) ||
      !reader.Secure(&signed_prekey_ec_private_.private_key)) {
    return Result<void>::Err("decode local state signed prekey ec failed: " + reader.error());
  }
  signed_prekey_ec_private_.public_key = signed_prekey_ec_public_.public_key;

  std::vector<uint8_t> signed_prekey_pq_private;
  if (!reader.U32(&signed_prekey_pq_public_.id) ||
      !reader.Bytes(&signed_prekey_pq_public_.public_key) ||
      !reader.Bytes(&signed_prekey_pq_public_.signature_ed25519) ||
      !reader.Bytes(&signed_prekey_pq_public_.signature_mldsa65) ||
      !reader.Bytes(&signed_prekey_pq_private)) {
    return Result<void>::Err("decode local state signed prekey pq failed: " + reader.error());
  }
  auto spk_pq = crypto::MlKem768::FromPrivateKey(signed_prekey_pq_private,
                                                 signed_prekey_pq_public_.public_key);
  if (!spk_pq.ok()) {
    return Result<void>::Err("restore signed prekey pq failed: " + spk_pq.error());
  }
  signed_prekey_pq_private_ = spk_pq.take_value();

  uint32_t one_time_ec_count = 0;
  if (!reader.U32(&one_time_ec_count) ||
      !reader.LimitU32(one_time_ec_count, static_cast<uint32_t>(kOneTimePrekeyPoolTarget * 64),
                       "one-time ec count")) {
    return Result<void>::Err("decode local state one-time ec count failed: " + reader.error());
  }
  one_time_ec_pool_.clear();
  one_time_ec_pool_.reserve(one_time_ec_count);
  for (uint32_t i = 0; i < one_time_ec_count; ++i) {
    OneTimeEc key;
    if (!reader.U32(&key.public_part.id) ||
        !reader.Bytes(&key.public_part.public_key) ||
        !reader.Secure(&key.private_part.private_key)) {
      return Result<void>::Err("decode local state one-time ec key failed: " + reader.error());
    }
    key.private_part.public_key = key.public_part.public_key;
    one_time_ec_pool_.push_back(std::move(key));
  }

  uint32_t one_time_pq_count = 0;
  if (!reader.U32(&one_time_pq_count) ||
      !reader.LimitU32(one_time_pq_count, static_cast<uint32_t>(kOneTimePrekeyPoolTarget * 64),
                       "one-time pq count")) {
    return Result<void>::Err("decode local state one-time pq count failed: " + reader.error());
  }
  one_time_pq_pool_.clear();
  one_time_pq_pool_.reserve(one_time_pq_count);
  for (uint32_t i = 0; i < one_time_pq_count; ++i) {
    OneTimePq key;
    std::vector<uint8_t> private_bytes;
    if (!reader.U32(&key.public_part.id) ||
        !reader.Bytes(&key.public_part.public_key) ||
        !reader.Bytes(&private_bytes)) {
      return Result<void>::Err("decode local state one-time pq key failed: " + reader.error());
    }
    auto pair = crypto::MlKem768::FromPrivateKey(private_bytes, key.public_part.public_key);
    if (!pair.ok()) {
      return Result<void>::Err("restore one-time pq key failed: " + pair.error());
    }
    key.private_part = pair.take_value();
    one_time_pq_pool_.push_back(std::move(key));
  }

  uint8_t prekeys_dirty = 0;
  if (!reader.U8(&prekeys_dirty)) {
    return Result<void>::Err("decode local state prekeys_dirty failed: " + reader.error());
  }
  prekeys_dirty_ = prekeys_dirty != 0;

  uint8_t has_pending_ack = 0;
  if (!reader.U8(&has_pending_ack)) {
    return Result<void>::Err("decode local state pending ack tag failed: " + reader.error());
  }
  if (has_pending_ack == 1) {
    uint64_t pending_ack = 0;
    if (!reader.U64(&pending_ack)) {
      return Result<void>::Err("decode local state pending ack failed: " + reader.error());
    }
    pending_inbox_ack_up_to_id_ = pending_ack;
  } else if (has_pending_ack == 0) {
    pending_inbox_ack_up_to_id_.reset();
  } else {
    return Result<void>::Err("decode local state pending ack tag invalid");
  }

  uint32_t trusted_count = 0;
  if (!reader.U32(&trusted_count) ||
      !reader.LimitU32(trusted_count, static_cast<uint32_t>(kMaxPersistedPeers),
                       "trusted peer count")) {
    return Result<void>::Err("decode local state trusted peers failed: " + reader.error());
  }
  trusted_peer_identities_.clear();
  for (uint32_t i = 0; i < trusted_count; ++i) {
    std::string peer_user;
    PeerIdentity peer;
    uint8_t verified = 0;
    if (!reader.String(&peer_user) ||
        !reader.Bytes(&peer.sign_public_key) ||
        !reader.Bytes(&peer.mldsa_public_key) ||
        !reader.Bytes(&peer.dh_public_key) ||
        !reader.U8(&verified)) {
      return Result<void>::Err("decode local state trusted peer failed: " + reader.error());
    }
    peer.verified = verified != 0;
    trusted_peer_identities_[peer_user] = std::move(peer);
  }

  uint32_t sessions_count = 0;
  if (!reader.U32(&sessions_count) ||
      !reader.LimitU32(sessions_count, static_cast<uint32_t>(kMaxPersistedSessions),
                       "session count")) {
    return Result<void>::Err("decode local state sessions failed: " + reader.error());
  }
  sessions_by_peer_.clear();
  for (uint32_t i = 0; i < sessions_count; ++i) {
    std::string peer_key;
    SessionState session;
    uint8_t is_initiator = 0;
    if (!reader.String(&peer_key) ||
        !reader.String(&session.session_id) ||
        !reader.String(&session.peer_user) ||
        !reader.U8(&is_initiator) ||
        !reader.Secure(&session.root_key) ||
        !reader.Secure(&session.send_chain_key) ||
        !reader.Secure(&session.recv_chain_key) ||
        !reader.U64(&session.send_counter) ||
        !reader.U64(&session.recv_counter) ||
        !reader.U64(&session.previous_send_chain_length) ||
        !reader.Secure(&session.local_ratchet_key.private_key) ||
        !reader.Bytes(&session.local_ratchet_key.public_key) ||
        !reader.Bytes(&session.remote_ratchet_public)) {
      return Result<void>::Err("decode local state session failed: " + reader.error());
    }
    session.is_initiator = is_initiator != 0;
    sessions_by_peer_[peer_key] = std::move(session);
  }

  uint32_t seen_session_count = 0;
  if (!reader.U32(&seen_session_count) ||
      !reader.LimitU32(seen_session_count,
                       static_cast<uint32_t>(kMaxInitialReplayGuards),
                       "seen initial session count")) {
    return Result<void>::Err("decode local state replay sessions failed: " + reader.error());
  }
  seen_initial_session_ids_.clear();
  seen_initial_session_order_.clear();
  for (uint32_t i = 0; i < seen_session_count; ++i) {
    std::string session_id;
    if (!reader.String(&session_id)) {
      return Result<void>::Err("decode local state replay session entry failed: " +
                               reader.error());
    }
    seen_initial_session_ids_.insert(session_id);
    seen_initial_session_order_.push_back(session_id);
  }

  uint32_t seen_transcript_count = 0;
  if (!reader.U32(&seen_transcript_count) ||
      !reader.LimitU32(seen_transcript_count,
                       static_cast<uint32_t>(kMaxInitialReplayGuards),
                       "seen initial transcript count")) {
    return Result<void>::Err("decode local state replay transcripts failed: " + reader.error());
  }
  seen_initial_transcript_hashes_.clear();
  seen_initial_transcript_order_.clear();
  for (uint32_t i = 0; i < seen_transcript_count; ++i) {
    std::string transcript;
    if (!reader.String(&transcript)) {
      return Result<void>::Err("decode local state replay transcript entry failed: " +
                               reader.error());
    }
    seen_initial_transcript_hashes_.insert(transcript);
    seen_initial_transcript_order_.push_back(transcript);
  }

  if (!reader.Finished()) {
    return Result<void>::Err("decode local state failed: trailing bytes");
  }
  return Result<void>::Ok();
}

Result<void> Client::HandleChatMessage(const protocol::ChatMessage& message,
                                       std::vector<std::string>* plaintext_out) {
  if (message.to_user != user_id_) {
    return Result<void>::Err("chat message recipient mismatch");
  }

  auto session_it = sessions_by_peer_.find(message.from_user);
  if (session_it == sessions_by_peer_.end()) {
    return Result<void>::Err("no session for incoming chat message");
  }

  auto& session = session_it->second;
  if (session.session_id != message.session_id) {
    return Result<void>::Err("session id mismatch");
  }

  if (message.header.sender_ratchet_public_key.has_value()) {
    const auto& new_remote = *message.header.sender_ratchet_public_key;
    if (new_remote != session.remote_ratchet_public) {
      auto dh = crypto::X25519::SharedSecret(session.local_ratchet_key.private_key,
                                             new_remote);
      if (!dh.ok()) {
        return Result<void>::Err("ratchet DH failed: " + dh.error());
      }

      auto mixed = DeriveRatchetRootAndChain(dh.value(), session.root_key);
      if (!mixed.ok()) {
        return Result<void>::Err("ratchet KDF failed: " + mixed.error());
      }

      session.recv_chain_key = crypto::SecureBuffer(std::move(mixed.value()[0]));
      session.root_key = crypto::SecureBuffer(std::move(mixed.value()[1]));
      session.remote_ratchet_public = new_remote;
      session.recv_counter = 0;
    }
  }

  if (message.header.message_number != session.recv_counter) {
    return Result<void>::Err("replay or out-of-order message rejected");
  }

  auto ad = protocol::BuildChatAssociatedData(message);
  if (!ad.ok()) {
    return Result<void>::Err("chat AD failed: " + ad.error());
  }

  auto plaintext = DecryptChainStep(&session.recv_chain_key,
                                    session.recv_counter,
                                    message.nonce,
                                    message.ciphertext,
                                    ad.value());
  if (!plaintext.ok()) {
    return Result<void>::Err("chat decrypt failed: " + plaintext.error());
  }

  session.recv_counter++;
  plaintext_out->push_back(
      std::string(plaintext.value().begin(), plaintext.value().end()));

  return Result<void>::Ok();
}

Result<void> Client::VerifyOrRememberPeerIdentity(
    const std::string& peer_user,
    const std::vector<uint8_t>& sign_public_key,
    const std::vector<uint8_t>& mldsa_public_key,
    const std::vector<uint8_t>& dh_public_key) {
  auto safety_number = ComputeSafetyNumber(peer_user,
                                           sign_public_key,
                                           mldsa_public_key,
                                           dh_public_key);
  if (!safety_number.ok()) {
    return Result<void>::Err(safety_number.error());
  }

  auto existing = trusted_peer_identities_.find(peer_user);
  if (existing == trusted_peer_identities_.end()) {
    trusted_peer_identities_[peer_user] =
        PeerIdentity{sign_public_key, mldsa_public_key, dh_public_key, false};
    auto save = SaveLocalState();
    if (!save.ok()) {
      return Result<void>::Err("persist local state failed: " + save.error());
    }
    return Result<void>::Err("peer identity is not verified; safety number: " +
                             safety_number.value());
  }

  if (existing->second.sign_public_key != sign_public_key ||
      existing->second.mldsa_public_key != mldsa_public_key ||
      existing->second.dh_public_key != dh_public_key) {
    return Result<void>::Err("peer identity key mismatch for trusted contact");
  }
  if (!existing->second.verified) {
    return Result<void>::Err("peer identity is not verified; safety number: " +
                             safety_number.value());
  }
  return Result<void>::Ok();
}

Result<std::string> Client::ComputeSafetyNumber(
    const std::string& peer_user,
    const std::vector<uint8_t>& sign_public_key,
    const std::vector<uint8_t>& mldsa_public_key,
    const std::vector<uint8_t>& dh_public_key) {
  std::vector<uint8_t> canonical;
  auto append_u32 = [&](uint32_t value) {
    canonical.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    canonical.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    canonical.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    canonical.push_back(static_cast<uint8_t>(value & 0xFF));
  };
  auto append_bytes = [&](const std::vector<uint8_t>& bytes) {
    append_u32(static_cast<uint32_t>(bytes.size()));
    canonical.insert(canonical.end(), bytes.begin(), bytes.end());
  };
  append_bytes(crypto::ToBytes("pqchat_peer_safety_number_v1"));
  append_bytes(crypto::ToBytes(peer_user));
  append_bytes(sign_public_key);
  append_bytes(mldsa_public_key);
  append_bytes(dh_public_key);

  auto hash = crypto::Sha256(canonical);
  if (!hash.ok()) {
    return Result<std::string>::Err(hash.error());
  }
  return Result<std::string>::Ok(HexEncode(hash.value()));
}

Result<void> Client::RememberInitialReplayGuards(
    const std::string& session_id,
    const std::vector<uint8_t>& transcript_hash) {
  const std::string transcript_key = HexEncode(transcript_hash);

  if (!seen_initial_session_ids_.insert(session_id).second) {
    return Result<void>::Err("duplicate initial session id rejected");
  }
  seen_initial_session_order_.push_back(session_id);

  if (!seen_initial_transcript_hashes_.insert(transcript_key).second) {
    seen_initial_session_ids_.erase(session_id);
    if (!seen_initial_session_order_.empty() &&
        seen_initial_session_order_.back() == session_id) {
      seen_initial_session_order_.pop_back();
    }
    return Result<void>::Err("duplicate initial transcript rejected");
  }
  seen_initial_transcript_order_.push_back(transcript_key);

  while (seen_initial_session_order_.size() > kMaxInitialReplayGuards) {
    const std::string oldest = seen_initial_session_order_.front();
    seen_initial_session_order_.pop_front();
    seen_initial_session_ids_.erase(oldest);
  }
  while (seen_initial_transcript_order_.size() > kMaxInitialReplayGuards) {
    const std::string oldest = seen_initial_transcript_order_.front();
    seen_initial_transcript_order_.pop_front();
    seen_initial_transcript_hashes_.erase(oldest);
  }
  return Result<void>::Ok();
}

bool Client::HasSeenInitialReplayGuard(
    const std::string& session_id,
    const std::vector<uint8_t>& transcript_hash) const {
  if (seen_initial_session_ids_.find(session_id) != seen_initial_session_ids_.end()) {
    return true;
  }
  const std::string transcript_key = HexEncode(transcript_hash);
  return seen_initial_transcript_hashes_.find(transcript_key) !=
         seen_initial_transcript_hashes_.end();
}

Result<std::string> Client::NewSessionId() {
  std::vector<uint8_t> random(16);
  if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
    return Result<std::string>::Err("RAND_bytes failed");
  }

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t b : random) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return Result<std::string>::Ok(oss.str());
}

}  // namespace pqchat::client
