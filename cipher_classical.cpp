#include <iostream>
#include <stdexcept>
#include <vector>

#include "cipher.h"
#include "ciphers.hpp"
#include "crypto_utils.hpp"


std::string simple_substitution_encrypt(std::string plaintext,
                                        std::string key) {
  try {
    crypto::SimpleSubstitutionCipher cipher(key);
    return cipher.Encrypt(plaintext);
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string simple_substitution_decrypt(std::string ciphertext,
                                        std::string key) {
  try {
    crypto::SimpleSubstitutionCipher cipher(key);
    return cipher.Decrypt(ciphertext);
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string simple_substitution_break(std::string ciphertext, int restarts) {
  try {
    auto res = crypto::SimpleSubstitutionCipher::Break(ciphertext, restarts);
    std::cout << "  " << res.key_description << "\n";
    std::cout << "  Fitness score: " << res.score << "\n";
    return res.plaintext;
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string hill_encrypt(std::string plaintext, std::vector<int> key_values,
                         int n) {
  try {
    crypto::Matrix key = crypto::Matrix::FromValues(n, n, key_values);
    crypto::HillCipher cipher(key);
    return cipher.Encrypt(plaintext);
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string hill_decrypt(std::string ciphertext, std::vector<int> key_values,
                         int n) {
  try {
    crypto::Matrix key = crypto::Matrix::FromValues(n, n, key_values);
    crypto::HillCipher cipher(key);
    std::string pt = cipher.Decrypt(ciphertext);
    // Срезать хвостовые символы дополнения X.
    while (!pt.empty() && pt.back() == 'X') pt.pop_back();
    return pt;
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string hill_break(std::string ciphertext) {
  try {
    auto res = crypto::HillCipher::Break(ciphertext, 2);
    std::cout << "  " << res.key_description << "\n";
    std::cout << "  Fitness score: " << res.score << "\n";
    std::string pt = res.plaintext;
    while (!pt.empty() && pt.back() == 'X') pt.pop_back();
    return pt;
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string recurrent_hill_encrypt(std::string plaintext,
                                   std::vector<std::vector<int>> keys_values,
                                   int n) {
  try {
    std::vector<crypto::Matrix> keys;
    for (auto& kv : keys_values)
      keys.push_back(crypto::Matrix::FromValues(n, n, kv));
    crypto::RecurrentHillCipher cipher(keys);
    return cipher.Encrypt(plaintext);
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string recurrent_hill_decrypt(std::string ciphertext,
                                   std::vector<std::vector<int>> keys_values,
                                   int n) {
  try {
    std::vector<crypto::Matrix> keys;
    for (auto& kv : keys_values)
      keys.push_back(crypto::Matrix::FromValues(n, n, kv));
    crypto::RecurrentHillCipher cipher(keys);
    std::string pt = cipher.Decrypt(ciphertext);
    while (!pt.empty() && pt.back() == 'X') pt.pop_back();
    return pt;
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}

std::string recurrent_hill_break(std::string ciphertext, int num_keys) {
  try {
    auto res = crypto::RecurrentHillCipher::Break(ciphertext, 2, num_keys);
    std::cout << "  " << res.key_description << "\n";
    std::cout << "  Fitness score: " << res.score << "\n";
    std::string pt = res.plaintext;
    while (!pt.empty() && pt.back() == 'X') pt.pop_back();
    return pt;
  } catch (const crypto::CipherError& e) {
    throw std::invalid_argument(e.what());
  }
}
