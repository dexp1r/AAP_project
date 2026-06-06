#include "crypto_utils.hpp"

#include <cctype>
#include <sstream>
#include <string>
#include <vector>

namespace crypto {

int Mod(long long value, int modulus) {
  if (modulus <= 0) {
    throw MatrixError("Modulus must be a positive integer.");
  }
  long long result = value % modulus;
  if (result < 0) {
    result += modulus;
  }
  return static_cast<int>(result);
}

int Gcd(int a, int b) {
  a = a < 0 ? -a : a;
  b = b < 0 ? -b : b;
  while (b != 0) {
    int temp = a % b;
    a = b;
    b = temp;
  }
  return a;
}

int ModInverse(int value, int modulus) {
  if (modulus <= 0) {
    throw MatrixError("Modulus must be a positive integer.");
  }
  // Расширенный алгоритм Евклида: отслеживаем коэффициент t при modulus.
  int normalized = Mod(value, modulus);
  int t = 0;
  int new_t = 1;
  int r = modulus;
  int new_r = normalized;
  while (new_r != 0) {
    int quotient = r / new_r;
    int tmp_t = t - quotient * new_t;
    t = new_t;
    new_t = tmp_t;
    int tmp_r = r - quotient * new_r;
    r = new_r;
    new_r = tmp_r;
  }
  if (r > 1) {
    throw NonInvertibleMatrixError("Value " + std::to_string(value) +
                                   " has no multiplicative inverse modulo " +
                                   std::to_string(modulus) + ".");
  }
  return Mod(t, modulus);
}

bool IsLetter(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

char ToUpperLetter(char c) {
  if (c >= 'a' && c <= 'z') {
    return static_cast<char>(c - 'a' + 'A');
  }
  return c;
}

std::string Normalize(const std::string& text) {
  std::string result;
  result.reserve(text.size());
  for (char c : text) {
    if (IsLetter(c)) {
      result.push_back(ToUpperLetter(c));
    }
  }
  return result;
}

int LetterToIndex(char c) {
  if (!IsLetter(c)) {
    throw InvalidInputError(std::string("Character '") + c +
                            "' is not a letter of the alphabet.");
  }
  return ToUpperLetter(c) - 'A';
}

char IndexToLetter(int index) {
  if (index < 0 || index >= kAlphabetSize) {
    throw InvalidInputError("Alphabet index " + std::to_string(index) +
                            " is out of range.");
  }
  return static_cast<char>('A' + index);
}

Matrix::Matrix(int rows, int cols, int modulus)
    : rows_(rows), cols_(cols), modulus_(modulus) {
  if (rows <= 0 || cols <= 0) {
    throw MatrixError("Matrix dimensions must be positive.");
  }
  if (modulus <= 0) {
    throw MatrixError("Matrix modulus must be positive.");
  }
  data_.assign(static_cast<std::size_t>(rows) * cols, 0);
}

Matrix Matrix::Identity(int size, int modulus) {
  Matrix result(size, size, modulus);
  for (int i = 0; i < size; ++i) {
    result.set(i, i, 1);
  }
  return result;
}

Matrix Matrix::FromValues(int rows, int cols, const std::vector<int>& values,
                          int modulus) {
  Matrix result(rows, cols, modulus);
  if (static_cast<int>(values.size()) != rows * cols) {
    throw MatrixError("Expected " + std::to_string(rows * cols) +
                      " matrix values but received " +
                      std::to_string(values.size()) + ".");
  }
  for (int r = 0; r < rows; ++r) {
    for (int c = 0; c < cols; ++c) {
      result.set(r, c, values[static_cast<std::size_t>(r) * cols + c]);
    }
  }
  return result;
}

int Matrix::at(int row, int col) const {
  if (row < 0 || row >= rows_ || col < 0 || col >= cols_) {
    throw MatrixError("Matrix element index out of bounds.");
  }
  return data_[static_cast<std::size_t>(row) * cols_ + col];
}

void Matrix::set(int row, int col, int value) {
  if (row < 0 || row >= rows_ || col < 0 || col >= cols_) {
    throw MatrixError("Matrix element index out of bounds.");
  }
  data_[static_cast<std::size_t>(row) * cols_ + col] = Mod(value, modulus_);
}

Matrix Matrix::Multiply(const Matrix& other) const {
  if (modulus_ != other.modulus_) {
    throw MatrixError("Cannot multiply matrices with different moduli.");
  }
  if (cols_ != other.rows_) {
    throw MatrixError("Matrix shapes are incompatible for multiplication.");
  }
  Matrix result(rows_, other.cols_, modulus_);
  for (int r = 0; r < rows_; ++r) {
    for (int c = 0; c < other.cols_; ++c) {
      long long sum = 0;
      for (int k = 0; k < cols_; ++k) {
        sum += static_cast<long long>(at(r, k)) * other.at(k, c);
      }
      result.set(r, c, Mod(sum, modulus_));
    }
  }
  return result;
}

std::vector<int> Matrix::MultiplyVector(const std::vector<int>& vec) const {
  if (static_cast<int>(vec.size()) != cols_) {
    throw MatrixError("Vector length does not match the number of columns.");
  }
  std::vector<int> result(static_cast<std::size_t>(rows_), 0);
  for (int r = 0; r < rows_; ++r) {
    long long sum = 0;
    for (int c = 0; c < cols_; ++c) {
      sum +=
          static_cast<long long>(at(r, c)) * vec[static_cast<std::size_t>(c)];
    }
    result[static_cast<std::size_t>(r)] = Mod(sum, modulus_);
  }
  return result;
}

Matrix Matrix::Minor(int skip_row, int skip_col) const {
  Matrix result(rows_ - 1, cols_ - 1, modulus_);
  int dest_row = 0;
  for (int r = 0; r < rows_; ++r) {
    if (r == skip_row) {
      continue;
    }
    int dest_col = 0;
    for (int c = 0; c < cols_; ++c) {
      if (c == skip_col) {
        continue;
      }
      result.set(dest_row, dest_col, at(r, c));
      ++dest_col;
    }
    ++dest_row;
  }
  return result;
}

int Matrix::DeterminantMod() const {
  if (!IsSquare()) {
    throw MatrixError("Determinant is only defined for square matrices.");
  }
  const int n = rows_;
  if (n == 1) {
    return at(0, 0);
  }
  if (n == 2) {
    long long det = static_cast<long long>(at(0, 0)) * at(1, 1) -
                    static_cast<long long>(at(0, 1)) * at(1, 0);
    return Mod(det, modulus_);
  }
  // Разложение Лапласа (по алгебраическим дополнениям первой строки).
  // Избегает деления по модулю, что делает вычисление корректным над кольцом
  // Z_26.
  long long det = 0;
  int sign = 1;
  for (int c = 0; c < n; ++c) {
    Matrix minor = Minor(0, c);
    det += static_cast<long long>(sign) * at(0, c) * minor.DeterminantMod();
    sign = -sign;
  }
  return Mod(det, modulus_);
}

Matrix Matrix::InverseMod() const {
  if (!IsSquare()) {
    throw MatrixError("Inverse is only defined for square matrices.");
  }
  const int n = rows_;
  const int determinant = DeterminantMod();
  // Генерирует NonInvertibleMatrixError, если определитель имеет общий
  // множитель с модулем (например, чётный или кратный 13 при модуле 26).
  const int det_inverse = ModInverse(determinant, modulus_);

  Matrix inverse(n, n, modulus_);
  if (n == 1) {
    inverse.set(0, 0, det_inverse);
    return inverse;
  }
  // inverse = det^{-1} * adjugate, где adjugate — транспонированная матрица
  // алгебраических дополнений.
  for (int r = 0; r < n; ++r) {
    for (int c = 0; c < n; ++c) {
      Matrix minor = Minor(r, c);
      int minor_det = minor.DeterminantMod();
      int sign = ((r + c) % 2 == 0) ? 1 : -1;
      int cofactor = Mod(static_cast<long long>(sign) * minor_det, modulus_);
      inverse.set(
          c, r, Mod(static_cast<long long>(det_inverse) * cofactor, modulus_));
    }
  }
  return inverse;
}

Matrix Matrix::Power(int exponent) const {
  if (!IsSquare()) {
    throw MatrixError("Only square matrices can be raised to a power.");
  }
  if (exponent < 1) {
    throw MatrixError("Matrix exponent must be a positive integer.");
  }
  // Быстрое (бинарное) возведение в степень.
  Matrix result = Identity(rows_, modulus_);
  Matrix base = *this;
  int e = exponent;
  while (e > 0) {
    if ((e & 1) != 0) {
      result = result.Multiply(base);
    }
    e >>= 1;
    if (e > 0) {
      base = base.Multiply(base);
    }
  }
  return result;
}

bool Matrix::operator==(const Matrix& other) const {
  return rows_ == other.rows_ && cols_ == other.cols_ &&
         modulus_ == other.modulus_ && data_ == other.data_;
}

std::string Matrix::ToString() const {
  std::ostringstream out;
  out << '[';
  for (int r = 0; r < rows_; ++r) {
    for (int c = 0; c < cols_; ++c) {
      out << at(r, c);
      if (c + 1 < cols_) {
        out << ' ';
      }
    }
    if (r + 1 < rows_) {
      out << "; ";
    }
  }
  out << ']';
  return out.str();
}

}  // namespace crypto
