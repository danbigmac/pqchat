#include "pqchat/server/tcp_wire.h"

#include <cerrno>
#include <cstring>
#include <string>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <sys/socket.h>
#include <unistd.h>

namespace pqchat::server {
namespace {

uint32_t LoadU32(const uint8_t* in) {
  return (static_cast<uint32_t>(in[0]) << 24) |
         (static_cast<uint32_t>(in[1]) << 16) |
         (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

void StoreU32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(value & 0xFF);
}

Result<void> ReadExact(int fd, uint8_t* out, size_t len, bool* eof) {
  *eof = false;
  size_t done = 0;
  while (done < len) {
    ssize_t n = recv(fd, out + done, len - done, 0);
    if (n == 0) {
      if (done == 0) {
        *eof = true;
        return Result<void>::Err("eof");
      }
      return Result<void>::Err("socket closed mid-frame");
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<void>::Err("recv failed: " + std::string(strerror(errno)));
    }
    done += static_cast<size_t>(n);
  }
  return Result<void>::Ok();
}

Result<void> WriteExact(int fd, const uint8_t* data, size_t len) {
  size_t done = 0;
  while (done < len) {
    ssize_t n = send(fd, data + done, len - done, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Result<void>::Err("send failed: " + std::string(strerror(errno)));
    }
    done += static_cast<size_t>(n);
  }
  return Result<void>::Ok();
}

std::string SslErrorString() {
  unsigned long error = ERR_get_error();
  if (error == 0) {
    return "unknown SSL error";
  }
  char buf[256];
  ERR_error_string_n(error, buf, sizeof(buf));
  return std::string(buf);
}

Result<void> ReadExactTls(SSL* ssl, uint8_t* out, size_t len, bool* eof) {
  if (ssl == nullptr) {
    return Result<void>::Err("SSL pointer is null");
  }

  *eof = false;
  size_t done = 0;
  while (done < len) {
    int n = SSL_read(ssl, out + done, static_cast<int>(len - done));
    if (n > 0) {
      done += static_cast<size_t>(n);
      continue;
    }

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      continue;
    }
    if (err == SSL_ERROR_ZERO_RETURN) {
      if (done == 0) {
        *eof = true;
        return Result<void>::Err("eof");
      }
      return Result<void>::Err("TLS connection closed mid-frame");
    }
    return Result<void>::Err("SSL_read failed: " + SslErrorString());
  }

  return Result<void>::Ok();
}

Result<void> WriteExactTls(SSL* ssl, const uint8_t* data, size_t len) {
  if (ssl == nullptr) {
    return Result<void>::Err("SSL pointer is null");
  }

  size_t done = 0;
  while (done < len) {
    int n = SSL_write(ssl, data + done, static_cast<int>(len - done));
    if (n > 0) {
      done += static_cast<size_t>(n);
      continue;
    }

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      continue;
    }
    return Result<void>::Err("SSL_write failed: " + SslErrorString());
  }

  return Result<void>::Ok();
}

}  // namespace

Result<void> WriteFrame(int fd, uint32_t type, const std::vector<uint8_t>& payload) {
  if (payload.size() > kMaxFramePayloadBytes) {
    return Result<void>::Err("frame payload too large");
  }

  uint8_t header[8];
  StoreU32(header, type);
  StoreU32(header + 4, static_cast<uint32_t>(payload.size()));

  auto write_header = WriteExact(fd, header, sizeof(header));
  if (!write_header.ok()) {
    return write_header;
  }

  if (!payload.empty()) {
    auto write_payload = WriteExact(fd, payload.data(), payload.size());
    if (!write_payload.ok()) {
      return write_payload;
    }
  }

  return Result<void>::Ok();
}

Result<void> WriteFrameTls(SSL* ssl,
                           uint32_t type,
                           const std::vector<uint8_t>& payload) {
  if (payload.size() > kMaxFramePayloadBytes) {
    return Result<void>::Err("frame payload too large");
  }

  uint8_t header[8];
  StoreU32(header, type);
  StoreU32(header + 4, static_cast<uint32_t>(payload.size()));

  auto write_header = WriteExactTls(ssl, header, sizeof(header));
  if (!write_header.ok()) {
    return write_header;
  }

  if (!payload.empty()) {
    auto write_payload = WriteExactTls(ssl, payload.data(), payload.size());
    if (!write_payload.ok()) {
      return write_payload;
    }
  }

  return Result<void>::Ok();
}

Result<std::pair<uint32_t, std::vector<uint8_t>>> ReadFrame(int fd) {
  uint8_t header[8];
  bool eof = false;
  auto read_header = ReadExact(fd, header, sizeof(header), &eof);
  if (!read_header.ok()) {
    return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(read_header.error());
  }

  uint32_t type = LoadU32(header);
  uint32_t payload_len = LoadU32(header + 4);
  if (payload_len > kMaxFramePayloadBytes) {
    return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(
        "frame payload too large");
  }

  std::vector<uint8_t> payload(payload_len);
  if (payload_len > 0) {
    auto read_payload = ReadExact(fd, payload.data(), payload.size(), &eof);
    if (!read_payload.ok()) {
      return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(
          read_payload.error());
    }
  }

  return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Ok(
      {type, std::move(payload)});
}

Result<std::pair<uint32_t, std::vector<uint8_t>>> ReadFrameTls(SSL* ssl) {
  uint8_t header[8];
  bool eof = false;
  auto read_header = ReadExactTls(ssl, header, sizeof(header), &eof);
  if (!read_header.ok()) {
    return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(read_header.error());
  }

  uint32_t type = LoadU32(header);
  uint32_t payload_len = LoadU32(header + 4);
  if (payload_len > kMaxFramePayloadBytes) {
    return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(
        "frame payload too large");
  }

  std::vector<uint8_t> payload(payload_len);
  if (payload_len > 0) {
    auto read_payload = ReadExactTls(ssl, payload.data(), payload.size(), &eof);
    if (!read_payload.ok()) {
      return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Err(
          read_payload.error());
    }
  }

  return Result<std::pair<uint32_t, std::vector<uint8_t>>>::Ok(
      {type, std::move(payload)});
}

}  // namespace pqchat::server
