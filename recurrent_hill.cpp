#include <limits>
#include <string>
#include <vector>

#include "ciphers.hpp"
#include "crypto_utils.hpp"
#include "language_model.hpp"

namespace crypto {

namespace {

/// Наибольший поддерживаемый порядок ключевых матриц.
constexpr int kMaxBlockSize = 8;

/// Символ-заполнитель для последнего неполного блока.
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

RecurrentHillCipher::RecurrentHillCipher(const std::vector<Matrix>& keys)
    : keys_(keys) {
  if (keys.empty()) {
    throw InvalidKeyError("The set of key matrices must not be empty.");
  }
  const int n = keys.front().rows();
  const int mod = keys.front().modulus();

  for (std::size_t idx = 0; idx < keys.size(); ++idx) {
    const Matrix& k = keys[idx];
    if (!k.IsSquare()) {
      throw InvalidKeyError("Matrix K" + std::to_string(idx + 1) +
                            " is not square.");
    }
    if (k.modulus() != kModulus) {
      throw InvalidKeyError("Matrix K" + std::to_string(idx + 1) +
                            " must use modulus 26.");
    }
    if (k.rows() != n || k.cols() != n) {
      throw InvalidKeyError("All key matrices must have the same order; K" +
                            std::to_string(idx + 1) + " has a different size.");
    }
    if (k.rows() < 1 || k.rows() > kMaxBlockSize) {
      throw InvalidKeyError("Unsupported block size " +
                            std::to_string(k.rows()) + " (allowed: 1.." +
                            std::to_string(kMaxBlockSize) + ").");
    }
    (void)mod;
    // Вычислить и сохранить обратную матрицу.
    try {
      inverse_keys_.push_back(k.InverseMod());
    } catch (const NonInvertibleMatrixError& error) {
      throw InvalidKeyError("Matrix K" + std::to_string(idx + 1) +
                            " is not invertible modulo 26: " + error.what());
    }
  }
}

std::string RecurrentHillCipher::Encrypt(const std::string& plaintext) const {
  std::string normalized = Normalize(plaintext);
  if (normalized.empty()) {
    throw InvalidInputError("Plaintext contains no alphabetic characters.");
  }
  const int n = block_size();
  const int m = key_count();
  std::vector<int> indices = ToPaddedIndices(normalized, n);

  std::string result;
  result.reserve(indices.size());
  std::vector<int> block(static_cast<std::size_t>(n), 0);
  int block_num = 0;  // номер текущего блока (0-based)
  for (std::size_t start = 0; start < indices.size();
       start += static_cast<std::size_t>(n), ++block_num) {
    // Матрица для блока block_num: K_{(block_num mod m)}
    const Matrix& key = keys_[static_cast<std::size_t>(block_num % m)];
    for (int i = 0; i < n; ++i) {
      block[static_cast<std::size_t>(i)] = indices[start + i];
    }
    std::vector<int> encrypted = key.MultiplyVector(block);
    for (int value : encrypted) {
      result.push_back(IndexToLetter(value));
    }
  }
  return result;
}

std::string RecurrentHillCipher::Decrypt(const std::string& ciphertext) const {
  std::string normalized = Normalize(ciphertext);
  if (normalized.empty()) {
    throw InvalidInputError("Ciphertext contains no alphabetic characters.");
  }
  const int n = block_size();
  const int m = key_count();
  if (normalized.size() % static_cast<std::size_t>(n) != 0) {
    throw InvalidInputError(
        "Ciphertext length (" + std::to_string(normalized.size()) +
        ") is not a multiple of the block size (" + std::to_string(n) + ").");
  }

  std::string result;
  result.reserve(normalized.size());
  std::vector<int> block(static_cast<std::size_t>(n), 0);
  int block_num = 0;
  for (std::size_t start = 0; start < normalized.size();
       start += static_cast<std::size_t>(n), ++block_num) {
    // Обратная матрица для позиции block_num % m
    const Matrix& inv = inverse_keys_[static_cast<std::size_t>(block_num % m)];
    for (int i = 0; i < n; ++i) {
      block[static_cast<std::size_t>(i)] = normalized[start + i] - 'A';
    }
    std::vector<int> decrypted = inv.MultiplyVector(block);
    for (int value : decrypted) {
      result.push_back(IndexToLetter(value));
    }
  }
  return result;
}

AttackResult RecurrentHillCipher::Break(const std::string& ciphertext,
                                        int block_size, int num_keys) {
  if (block_size != 2) {
    throw CryptanalysisError(
        "Brute-force recovery is only feasible for block size 2 (2x2 matrix).");
  }
  if (num_keys < 1) {
    throw CryptanalysisError("The number of key matrices must be at least 1.");
  }
  std::string normalized = Normalize(ciphertext);
  if (normalized.size() < 4) {
    throw CryptanalysisError(
        "Ciphertext is too short for a brute-force recurrent Hill attack.");
  }

  // Используется целое число двухбуквенных блоков.
  std::size_t usable = normalized.size() - (normalized.size() % 2);
  int total_blocks = static_cast<int>(usable / 2);

  if (total_blocks < num_keys) {
    throw CryptanalysisError("Ciphertext has fewer blocks (" +
                             std::to_string(total_blocks) +
                             ") than the number of key matrices (" +
                             std::to_string(num_keys) + ").");
  }

  // Преобразовать шифртекст в числовые индексы.
  std::vector<int> all_idx;
  all_idx.reserve(usable);
  for (std::size_t i = 0; i < usable; ++i) {
    all_idx.push_back(normalized[i] - 'A');
  }

  const LanguageModel model;
  std::vector<Matrix> best_keys(static_cast<std::size_t>(num_keys),
                                Matrix::Identity(2));
  // Для каждой позиции — восстановленные индексы букв открытого текста.
  std::vector<std::vector<int>> stream_plain(
      static_cast<std::size_t>(num_keys));

  // Независимый перебор для каждой позиции ключевого цикла.
  for (int key_pos = 0; key_pos < num_keys; ++key_pos) {
    // Собрать «поток» — блоки, зашифрованные матрицей key_pos+1.
    std::vector<int> stream;
    for (int b = key_pos; b < total_blocks; b += num_keys) {
      stream.push_back(all_idx[static_cast<std::size_t>(b * 2)]);
      stream.push_back(all_idx[static_cast<std::size_t>(b * 2 + 1)]);
    }

    double best_score = -std::numeric_limits<double>::infinity();
    Matrix best_key = Matrix::Identity(2);
    std::vector<int> best_plain(stream.size(), 0);
    std::vector<int> plain(stream.size(), 0);

    // Перебор всех матриц [[a,b],[c,d]] над Z_26.
    for (int a = 0; a < kModulus; ++a) {
      for (int b = 0; b < kModulus; ++b) {
        for (int c = 0; c < kModulus; ++c) {
          for (int d = 0; d < kModulus; ++d) {
            int det = Mod(a * d - b * c, kModulus);
            if (Gcd(det, kModulus) != 1) {
              continue;  // Не является обратимой матрицей.
            }
            Matrix key = Matrix::FromValues(2, 2, {a, b, c, d});
            Matrix inv = Matrix::Identity(2);
            try {
              inv = key.InverseMod();
            } catch (const NonInvertibleMatrixError&) {
              continue;
            }
            // Расшифровать поток кандидатом обратной матрицы.
            const int i00 = inv.at(0, 0), i01 = inv.at(0, 1);
            const int i10 = inv.at(1, 0), i11 = inv.at(1, 1);
            for (std::size_t p = 0; p < stream.size(); p += 2) {
              plain[p] = Mod(i00 * stream[p] + i01 * stream[p + 1], kModulus);
              plain[p + 1] =
                  Mod(i10 * stream[p] + i11 * stream[p + 1], kModulus);
            }
            // Оценка по триграммам.
            double score = 0.0;
            for (std::size_t i = 2; i < plain.size(); ++i) {
              score += model.Trigram(plain[i - 2], plain[i - 1], plain[i]);
            }
            if (score > best_score) {
              best_score = score;
              best_key = key;
              best_plain = plain;
            }
          }
        }
      }
    }

    best_keys[static_cast<std::size_t>(key_pos)] = best_key;
    stream_plain[static_cast<std::size_t>(key_pos)] = best_plain;
  }

  // Собрать открытый текст, расставив блоки в исходном порядке.
  std::string recovered;
  recovered.resize(usable);
  std::vector<std::size_t> stream_idx(static_cast<std::size_t>(num_keys), 0);
  for (int b = 0; b < total_blocks; ++b) {
    std::size_t kp = static_cast<std::size_t>(b % num_keys);
    std::size_t si = stream_idx[kp];
    recovered[static_cast<std::size_t>(b * 2)] =
        IndexToLetter(stream_plain[kp][si]);
    recovered[static_cast<std::size_t>(b * 2 + 1)] =
        IndexToLetter(stream_plain[kp][si + 1]);
    stream_idx[kp] += 2;
  }

  // Сформировать описание найденных ключей.
  std::string key_desc =
      "recovered " + std::to_string(num_keys) + " key matrix(ces):";
  double total_score = 0.0;
  for (int j = 0; j < num_keys; ++j) {
    key_desc += " K" + std::to_string(j + 1) + "=" +
                best_keys[static_cast<std::size_t>(j)].ToString();
    // Пересчитать оценку каждого потока (сумма по потокам).
    const auto& sp = stream_plain[static_cast<std::size_t>(j)];
    for (std::size_t i = 2; i < sp.size(); ++i) {
      total_score += model.Trigram(sp[i - 2], sp[i - 1], sp[i]);
    }
  }

  AttackResult result;
  result.key_description = key_desc;
  result.plaintext = recovered;
  result.score = total_score;
  return result;
}

}  // namespace crypto
