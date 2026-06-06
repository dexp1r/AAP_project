#ifndef CLASSICAL_CIPHERS_CRYPTO_UTILS_HPP_
#define CLASSICAL_CIPHERS_CRYPTO_UTILS_HPP_

#include <stdexcept>
#include <string>
#include <vector>

namespace crypto {

class CipherError : public std::runtime_error {
 public:
  explicit CipherError(const std::string& message)
      : std::runtime_error(message) {}
};

class InvalidKeyError : public CipherError {
 public:
  explicit InvalidKeyError(const std::string& message) : CipherError(message) {}
};

class InvalidInputError : public CipherError {
 public:
  explicit InvalidInputError(const std::string& message)
      : CipherError(message) {}
};

class MatrixError : public CipherError {
 public:
  explicit MatrixError(const std::string& message) : CipherError(message) {}
};

class NonInvertibleMatrixError : public CipherError {
 public:
  explicit NonInvertibleMatrixError(const std::string& message)
      : CipherError(message) {}
};

class CryptanalysisError : public CipherError {
 public:
  explicit CryptanalysisError(const std::string& message)
      : CipherError(message) {}
};

/* ====================================================================== */
/* НАЧАЛО ЗАИМСТВОВАННОГО ФРАГМЕНТА (стандартный латинский алфавит A..Z)   */
/* Источник: ISO basic Latin alphabet, общественное достояние.            */

inline constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/* КОНЕЦ ЗАИМСТВОВАННОГО ФРАГМЕНТА                                         */
/* ====================================================================== */

inline constexpr int kAlphabetSize = 26;

inline constexpr int kModulus = 26;

int Mod(long long value, int modulus = kModulus);

int Gcd(int a, int b);

int ModInverse(int value, int modulus = kModulus);

bool IsLetter(char c);

char ToUpperLetter(char c);

std::string Normalize(const std::string& text);

int LetterToIndex(char c);

char IndexToLetter(int index);

class Matrix {
 public:
  Matrix(int rows, int cols, int modulus = kModulus);

  static Matrix Identity(int size, int modulus = kModulus);

  static Matrix FromValues(int rows, int cols, const std::vector<int>& values,
                           int modulus = kModulus);

  int rows() const { return rows_; }

  int cols() const { return cols_; }

  int modulus() const { return modulus_; }

  int at(int row, int col) const;

  void set(int row, int col, int value);

  bool IsSquare() const { return rows_ == cols_; }

  Matrix Multiply(const Matrix& other) const;

  std::vector<int> MultiplyVector(const std::vector<int>& vec) const;

  int DeterminantMod() const;

  Matrix InverseMod() const;

  Matrix Power(int exponent) const;

  bool operator==(const Matrix& other) const;

  std::string ToString() const;

 private:
  Matrix Minor(int skip_row, int skip_col) const;

  int rows_;     ///< Число строк.
  int cols_;     ///< Число столбцов.
  int modulus_;  ///< Модуль для всей арифметики.
  std::vector<int>
      data_;  ///< Элементы в строчно-мажорном порядке, размер rows_*cols_.
};

}  // namespace crypto

#endif  // CLASSICAL_CIPHERS_CRYPTO_UTILS_HPP_
