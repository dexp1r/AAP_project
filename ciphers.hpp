#ifndef CLASSICAL_CIPHERS_CIPHERS_HPP_
#define CLASSICAL_CIPHERS_CIPHERS_HPP_

#include <array>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace crypto {

struct AttackResult {
  std::string key_description;  ///< Удобочитаемое описание найденного ключа.
  std::string plaintext;  ///< Лучший восстановленный открытый текст.
  double score = 0.0;  ///< Оценка качества восстановленного текста.
};

class SimpleSubstitutionCipher {
 public:
  explicit SimpleSubstitutionCipher(const std::string& cipher_alphabet);

  std::string Encrypt(const std::string& plaintext) const;

  std::string Decrypt(const std::string& ciphertext) const;

  const std::string& key() const { return cipher_alphabet_; }

  static AttackResult Break(const std::string& ciphertext, int restarts = 60);

 private:
  std::string cipher_alphabet_;
  /// Таблица шифрования: индекс буквы открытого текста → индекс шифртекста.
  std::array<int, kAlphabetSize> encrypt_map_;
  /// Таблица расшифрования: индекс буквы шифртекста → индекс открытого текста.
  std::array<int, kAlphabetSize> decrypt_map_;
};

class HillCipher {
 public:
  explicit HillCipher(const Matrix& key);

  std::string Encrypt(const std::string& plaintext) const;

  std::string Decrypt(const std::string& ciphertext) const;

  int block_size() const { return key_.rows(); }

  const Matrix& key() const { return key_; }

  static AttackResult Break(const std::string& ciphertext, int block_size = 2);

 private:
  Matrix key_;          ///< Матрица ключа шифрования.
  Matrix inverse_key_;  ///< Кешированная обратная матрица для расшифрования.
};

class RecurrentHillCipher {
 public:
  explicit RecurrentHillCipher(const std::vector<Matrix>& keys);

  std::string Encrypt(const std::string& plaintext) const;

  std::string Decrypt(const std::string& ciphertext) const;

  int block_size() const { return keys_.front().rows(); }

  int key_count() const { return static_cast<int>(keys_.size()); }

  const std::vector<Matrix>& keys() const { return keys_; }

  static AttackResult Break(const std::string& ciphertext, int block_size = 2,
                            int num_keys = 1);

 private:
  std::vector<Matrix> keys_;  ///< Набор ключевых матриц K_1…K_m.
  std::vector<Matrix> inverse_keys_;  ///< Обратные матрицы для расшифрования.
};

}  // namespace crypto

#endif  // CLASSICAL_CIPHERS_CIPHERS_HPP_
