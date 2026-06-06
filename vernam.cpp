#include "cipher.h"
#include <stdexcept>

std::string ALPHABET1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ,.;'";
int ALPHABET_LENGTH1 = 31;

std::string vernam_encryption(std::string plaintext, std::string key) {
    plaintext = to_upper(plaintext);
    key = to_upper(key);
    check_is_english(plaintext);
    check_is_english(key);

    if (plaintext.length() != key.length()) {
        throw std::invalid_argument("Vernam cipher requires the key to be exactly the same length as the text.");
    }

    std::string cipher = plaintext;
    for (size_t i = 0; i < plaintext.length(); i++) {
        cipher[i] = ALPHABET1[(ALPHABET1.find(plaintext[i]) + ALPHABET1.find(key[i])) % ALPHABET_LENGTH1];
    }
    return cipher;
}

std::string vernam_decryption(std::string ciphertext, std::string key) {
    ciphertext = to_upper(ciphertext);
    key = to_upper(key);
    check_is_english(ciphertext);
    check_is_english(key);

    if (ciphertext.length() != key.length()) {
        throw std::invalid_argument("Vernam cipher requires the key to be exactly the same length as the text.");
    }

    std::string plain = ciphertext;
    for (size_t i = 0; i < ciphertext.length(); i++) {
        int val = ALPHABET1.find(ciphertext[i]) - ALPHABET1.find(key[i]);
        if (val < 0) val += ALPHABET_LENGTH1;
        plain[i] = ALPHABET1[val];
    }
    return plain;
}
