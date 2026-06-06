#ifndef CLASSICAL_CIPHERS_LANGUAGE_MODEL_HPP_
#define CLASSICAL_CIPHERS_LANGUAGE_MODEL_HPP_

#include <array>
#include <string>

#include "crypto_utils.hpp"

namespace crypto {

extern const std::array<double, kAlphabetSize> kEnglishLetterFrequency;

extern const std::string kFrequencyOrder;

class LanguageModel {
 public:
  LanguageModel();

  double Trigram(int a, int b, int c) const;

  double Bigram(int first, int second) const;

  double Score(const std::string& text) const;

  const std::string& frequency_order() const { return frequency_order_; }

 private:
  /// Плоская таблица 26^3 = 17576 десятичных логарифмов вероятностей триграмм.
  /// Индекс: a*26*26 + b*26 + c.
  std::array<double, kAlphabetSize * kAlphabetSize * kAlphabetSize>
      trigram_log_;
  /// Логарифм вероятности для триграмм, отсутствующих в таблице.
  double floor_log_;
  /// Кешированная копия ::crypto::kFrequencyOrder.
  std::string frequency_order_;
};

}  // namespace crypto

#endif  // CLASSICAL_CIPHERS_LANGUAGE_MODEL_HPP_
