#pragma once

#include <optional>
#include <string>
#include <utility>

namespace pqchat {

template <typename T>
class Result {
 public:
  static Result<T> Ok(T value) {
    Result<T> result;
    result.value_ = std::move(value);
    return result;
  }

  static Result<T> Err(std::string error) {
    Result<T> result;
    result.error_ = std::move(error);
    return result;
  }

  [[nodiscard]] bool ok() const { return error_.empty(); }
  [[nodiscard]] const std::string& error() const { return error_; }

  [[nodiscard]] const T& value() const { return *value_; }
  [[nodiscard]] T& value() { return *value_; }
  [[nodiscard]] T&& take_value() { return std::move(*value_); }

 private:
  Result() = default;

  std::optional<T> value_;
  std::string error_;
};

template <>
class Result<void> {
 public:
  static Result<void> Ok() { return Result<void>(); }
  static Result<void> Err(std::string error) { return Result<void>(std::move(error)); }

  [[nodiscard]] bool ok() const { return error_.empty(); }
  [[nodiscard]] const std::string& error() const { return error_; }

 private:
  Result() = default;
  explicit Result(std::string error) : error_(std::move(error)) {}

  std::string error_;
};

}  // namespace pqchat
