#include <algorithm>
#include <array>
#include <numeric>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "ciphers.hpp"
#include "crypto_utils.hpp"
#include "language_model.hpp"

namespace crypto {

namespace {

double ScoreMapping(const std::array<int, kAlphabetSize>& decrypt_map,
                    const std::vector<int>& cipher_indices,
                    const LanguageModel& model) {
  if (cipher_indices.size() < 3) {
    return 0.0;
  }
  double total = 0.0;
  int prev2 = decrypt_map[static_cast<std::size_t>(cipher_indices[0])];
  int prev1 = decrypt_map[static_cast<std::size_t>(cipher_indices[1])];
  for (std::size_t i = 2; i < cipher_indices.size(); ++i) {
    int current = decrypt_map[static_cast<std::size_t>(cipher_indices[i])];
    total += model.Trigram(prev2, prev1, current);
    prev2 = prev1;
    prev1 = current;
  }
  return total;
}

std::array<int, kAlphabetSize> FrequencyInitialMap(
    const std::vector<int>& cipher_indices,
    const std::string& frequency_order) {
  std::array<long long, kAlphabetSize> counts{};
  counts.fill(0);
  for (int index : cipher_indices) {
    ++counts[static_cast<std::size_t>(index)];
  }
  // Упорядочить буквы шифртекста по убыванию частоты (устойчивая сортировка
  // по индексу буквы для детерминированности).
  std::array<int, kAlphabetSize> cipher_by_count;
  std::iota(cipher_by_count.begin(), cipher_by_count.end(), 0);
  std::stable_sort(cipher_by_count.begin(), cipher_by_count.end(),
                   [&counts](int lhs, int rhs) {
                     return counts[static_cast<std::size_t>(lhs)] >
                            counts[static_cast<std::size_t>(rhs)];
                   });
  std::array<int, kAlphabetSize> decrypt_map{};
  decrypt_map.fill(0);
  for (int rank = 0; rank < kAlphabetSize; ++rank) {
    int cipher_letter = cipher_by_count[static_cast<std::size_t>(rank)];
    int plain_letter = frequency_order[static_cast<std::size_t>(rank)] - 'A';
    decrypt_map[static_cast<std::size_t>(cipher_letter)] = plain_letter;
  }
  return decrypt_map;
}

double HillClimb(std::array<int, kAlphabetSize>& decrypt_map,
                 const std::vector<int>& cipher_indices,
                 const LanguageModel& model) {
  double best_score = ScoreMapping(decrypt_map, cipher_indices, model);
  bool improved = true;
  while (improved) {
    improved = false;
    for (int i = 0; i < kAlphabetSize; ++i) {
      for (int j = i + 1; j < kAlphabetSize; ++j) {
        std::swap(decrypt_map[static_cast<std::size_t>(i)],
                  decrypt_map[static_cast<std::size_t>(j)]);
        double candidate = ScoreMapping(decrypt_map, cipher_indices, model);
        if (candidate > best_score) {
          best_score = candidate;
          improved = true;
        } else {
          std::swap(decrypt_map[static_cast<std::size_t>(i)],
                    decrypt_map[static_cast<std::size_t>(j)]);
        }
      }
    }
  }
  return best_score;
}

}  // namespace

SimpleSubstitutionCipher::SimpleSubstitutionCipher(
    const std::string& cipher_alphabet) {
  std::string normalized = Normalize(cipher_alphabet);
  if (static_cast<int>(normalized.size()) != kAlphabetSize) {
    throw InvalidKeyError(
        "The substitution key must contain exactly 26 letters; got " +
        std::to_string(normalized.size()) + ".");
  }
  std::array<bool, kAlphabetSize> seen{};
  seen.fill(false);
  for (char c : normalized) {
    int index = c - 'A';
    if (seen[static_cast<std::size_t>(index)]) {
      throw InvalidKeyError(
          "The substitution key must be a permutation; letter '" +
          std::string(1, c) + "' appears more than once.");
    }
    seen[static_cast<std::size_t>(index)] = true;
  }

  cipher_alphabet_ = normalized;
  encrypt_map_.fill(0);
  decrypt_map_.fill(0);
  for (int plain = 0; plain < kAlphabetSize; ++plain) {
    int cipher = normalized[static_cast<std::size_t>(plain)] - 'A';
    encrypt_map_[static_cast<std::size_t>(plain)] = cipher;
    decrypt_map_[static_cast<std::size_t>(cipher)] = plain;
  }
}

std::string SimpleSubstitutionCipher::Encrypt(
    const std::string& plaintext) const {
  std::string normalized = Normalize(plaintext);
  if (normalized.empty()) {
    throw InvalidInputError("Plaintext contains no alphabetic characters.");
  }
  std::string result;
  result.reserve(normalized.size());
  for (char c : normalized) {
    int plain = c - 'A';
    result.push_back(
        IndexToLetter(encrypt_map_[static_cast<std::size_t>(plain)]));
  }
  return result;
}

std::string SimpleSubstitutionCipher::Decrypt(
    const std::string& ciphertext) const {
  std::string normalized = Normalize(ciphertext);
  if (normalized.empty()) {
    throw InvalidInputError("Ciphertext contains no alphabetic characters.");
  }
  std::string result;
  result.reserve(normalized.size());
  for (char c : normalized) {
    int cipher = c - 'A';
    result.push_back(
        IndexToLetter(decrypt_map_[static_cast<std::size_t>(cipher)]));
  }
  return result;
}

AttackResult SimpleSubstitutionCipher::Break(const std::string& ciphertext,
                                             int restarts) {
  if (restarts < 1) {
    throw InvalidInputError("The number of restarts must be positive.");
  }
  std::string normalized = Normalize(ciphertext);
  if (normalized.size() < 2) {
    throw CryptanalysisError(
        "Ciphertext is too short for automated frequency analysis.");
  }

  std::vector<int> cipher_indices;
  cipher_indices.reserve(normalized.size());
  for (char c : normalized) {
    cipher_indices.push_back(c - 'A');
  }

  const LanguageModel model;
  // Детерминированный генератор: результаты воспроизводимы от запуска к
  // запуску.
  std::mt19937 rng(0xC1A5Du);

  std::array<int, kAlphabetSize> best_map =
      FrequencyInitialMap(cipher_indices, model.frequency_order());
  double best_score = HillClimb(best_map, cipher_indices, model);

  std::array<int, kAlphabetSize> candidate;
  std::iota(candidate.begin(), candidate.end(), 0);
  for (int attempt = 1; attempt < restarts; ++attempt) {
    std::shuffle(candidate.begin(), candidate.end(), rng);
    double score = HillClimb(candidate, cipher_indices, model);
    if (score > best_score) {
      best_score = score;
      best_map = candidate;
    }
  }

  // Восстановить шифралфавит (обратное отображение лучшей таблицы
  // расшифрования) и соответствующий открытый текст.
  std::array<int, kAlphabetSize> encrypt_map{};
  encrypt_map.fill(0);
  for (int cipher = 0; cipher < kAlphabetSize; ++cipher) {
    int plain = best_map[static_cast<std::size_t>(cipher)];
    encrypt_map[static_cast<std::size_t>(plain)] = cipher;
  }
  std::string recovered_key;
  recovered_key.reserve(kAlphabetSize);
  for (int plain = 0; plain < kAlphabetSize; ++plain) {
    recovered_key.push_back(
        IndexToLetter(encrypt_map[static_cast<std::size_t>(plain)]));
  }
  std::string plaintext;
  plaintext.reserve(cipher_indices.size());
  for (int index : cipher_indices) {
    plaintext.push_back(
        IndexToLetter(best_map[static_cast<std::size_t>(index)]));
  }

  AttackResult result;
  result.key_description = "recovered cipher alphabet (A->): " + recovered_key;
  result.plaintext = plaintext;
  result.score = best_score;
  return result;
}

}  // namespace crypto
