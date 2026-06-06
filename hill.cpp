#include <limits>
#include <string>
#include <vector>

#include "ciphers.hpp"
#include "crypto_utils.hpp"
#include "language_model.hpp"

namespace crypto {

namespace {

/// Наибольший поддерживаемый порядок ключевой матрицы. Определитель вычисляется
/// разложением по дополнениям, поэтому очень большие матрицы отвергаются
/// заранее.
constexpr int kMaxBlockSize = 8;

/// Символ-заполнитель, дополняющий последний неполный блок.
constexpr char kPaddingLetter = 'X';

std::vector<int> ToPaddedIndices(const std::string& text, int block_size) {
  std::vector<int> indices;
  indices.reserve(text.size() + static_cast<std::size_t>(block_size));
  for (char c : text) {
    indices.push_back(c - 'A');
  }
  while (indices.size() % static_cast<std::size_t>(block_size) != 0) {
    indices.push_back(kPaddingLetter - 'A');
  }
  return indices;
}

}  // namespace

HillCipher::HillCipher(const Matrix& key) : key_(key), inverse_key_(key) {
  if (!key.IsSquare()) {
    throw InvalidKeyError("The Hill key matrix must be square.");
  }
  if (key.modulus() != kModulus) {
    throw InvalidKeyError("The Hill key matrix must use modulus 26.");
  }
  if (key.rows() < 1 || key.rows() > kMaxBlockSize) {
    throw InvalidKeyError("Unsupported Hill block size " +
                          std::to_string(key.rows()) + " (allowed: 1.." +
                          std::to_string(kMaxBlockSize) + ").");
  }
  // Вычисление обратной матрицы здесь же проверяет обратимость; низкоуровневая
  // ошибка переводится в ошибку ключа для вызывающего кода.
  try {
    inverse_key_ = key.InverseMod();
  } catch (const NonInvertibleMatrixError& error) {
    throw InvalidKeyError(std::string("The Hill key is not invertible modulo "
                                      "26: ") +
                          error.what());
  }
}

std::string HillCipher::Encrypt(const std::string& plaintext) const {
  std::string normalized = Normalize(plaintext);
  if (normalized.empty()) {
    throw InvalidInputError("Plaintext contains no alphabetic characters.");
  }
  const int n = block_size();
  std::vector<int> indices = ToPaddedIndices(normalized, n);

  std::string result;
  result.reserve(indices.size());
  std::vector<int> block(static_cast<std::size_t>(n), 0);
  for (std::size_t start = 0; start < indices.size();
       start += static_cast<std::size_t>(n)) {
    for (int i = 0; i < n; ++i) {
      block[static_cast<std::size_t>(i)] = indices[start + i];
    }
    std::vector<int> encrypted = key_.MultiplyVector(block);
    for (int value : encrypted) {
      result.push_back(IndexToLetter(value));
    }
  }
  return result;
}

std::string HillCipher::Decrypt(const std::string& ciphertext) const {
  std::string normalized = Normalize(ciphertext);
  if (normalized.empty()) {
    throw InvalidInputError("Ciphertext contains no alphabetic characters.");
  }
  const int n = block_size();
  if (normalized.size() % static_cast<std::size_t>(n) != 0) {
    throw InvalidInputError(
        "Ciphertext length (" + std::to_string(normalized.size()) +
        ") is not a multiple of the block size (" + std::to_string(n) + ").");
  }

  std::string result;
  result.reserve(normalized.size());
  std::vector<int> block(static_cast<std::size_t>(n), 0);
  for (std::size_t start = 0; start < normalized.size();
       start += static_cast<std::size_t>(n)) {
    for (int i = 0; i < n; ++i) {
      block[static_cast<std::size_t>(i)] = normalized[start + i] - 'A';
    }
    std::vector<int> decrypted = inverse_key_.MultiplyVector(block);
    for (int value : decrypted) {
      result.push_back(IndexToLetter(value));
    }
  }
  return result;
}

AttackResult HillCipher::Break(const std::string& ciphertext, int block_size) {
  if (block_size != 2) {
    throw CryptanalysisError(
        "Brute-force recovery is only feasible for a 2x2 key (block size 2). "
        "For larger blocks the key space is computationally intractable.");
  }
  std::string normalized = Normalize(ciphertext);
  if (normalized.size() < 4) {
    throw CryptanalysisError(
        "Ciphertext is too short for a brute-force Hill attack.");
  }
  // Используется целое число двухбуквенных блоков; одиночный «хвостовой» символ
  // отбрасывается.
  std::size_t usable = normalized.size() - (normalized.size() % 2);
  std::vector<int> cipher_indices;
  cipher_indices.reserve(usable);
  for (std::size_t i = 0; i < usable; ++i) {
    cipher_indices.push_back(normalized[i] - 'A');
  }

  const LanguageModel model;
  double best_score = -std::numeric_limits<double>::infinity();
  Matrix best_key = Matrix::Identity(2);
  std::string best_plaintext;
  std::vector<int> plaintext(usable, 0);

  // Перебираем все матрицы [[a,b],[c,d]] над Z_26.
  for (int a = 0; a < kModulus; ++a) {
    for (int b = 0; b < kModulus; ++b) {
      for (int c = 0; c < kModulus; ++c) {
        for (int d = 0; d < kModulus; ++d) {
          int determinant = Mod(a * d - b * c, kModulus);
          if (Gcd(determinant, kModulus) != 1) {
            continue;  // Необратима: не может быть допустимым ключом.
          }
          Matrix key = Matrix::FromValues(2, 2, {a, b, c, d});
          Matrix inverse = Matrix::Identity(2);
          try {
            inverse = key.InverseMod();
          } catch (const NonInvertibleMatrixError&) {
            continue;  // Защитная проверка: пропустить, если обращение
                       // неожиданно провалилось.
          }
          // Расшифровать каждый блок кандидатом обратной матрицы и оценить
          // результат.
          const int i00 = inverse.at(0, 0);
          const int i01 = inverse.at(0, 1);
          const int i10 = inverse.at(1, 0);
          const int i11 = inverse.at(1, 1);
          for (std::size_t pos = 0; pos < usable; pos += 2) {
            int x = cipher_indices[pos];
            int y = cipher_indices[pos + 1];
            plaintext[pos] = Mod(i00 * x + i01 * y, kModulus);
            plaintext[pos + 1] = Mod(i10 * x + i11 * y, kModulus);
          }
          double score = 0.0;
          for (std::size_t i = 2; i < usable; ++i) {
            score +=
                model.Trigram(plaintext[i - 2], plaintext[i - 1], plaintext[i]);
          }
          if (score > best_score) {
            best_score = score;
            best_key = key;
            best_plaintext.assign(usable, 'A');
            for (std::size_t i = 0; i < usable; ++i) {
              best_plaintext[i] = IndexToLetter(plaintext[i]);
            }
          }
        }
      }
    }
  }

  AttackResult result;
  result.key_description = "recovered key matrix " + best_key.ToString();
  result.plaintext = best_plaintext;
  result.score = best_score;
  return result;
}

}  // namespace crypto
