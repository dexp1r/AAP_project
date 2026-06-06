#include "cipher.h"
#include <iostream>
#include <numeric>
#include <stdexcept>

int inverse_by_mod(int number, int mod) {
    for (int i = 1; i <= mod; i++) {
        if (i * number % mod == 1) {
            return i;
        }
    }
    throw std::invalid_argument(
        "Key a must be coprime with the alphabet length (26)");
}

std::string affine_encryption(std::string plaintext, int alpha_key,
                              int beta_key) {
    if (plaintext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(plaintext);

    if (std::gcd(alpha_key, ALPHABET_LENGTH) != 1) {
        throw std::invalid_argument(
            "Key a must be coprime with the alphabet length (26)");
    }

    plaintext = to_upper(plaintext);
    std::string ciphertext;

    for (char letter : plaintext) {
        if (ALPHABET.find(letter) != std::string::npos) {
            int x = ALPHABET.find(letter);
            int y = (alpha_key * x + beta_key) % ALPHABET_LENGTH;
            ciphertext += ALPHABET[y];
        } else {
            ciphertext += letter;
        }
    }
    return ciphertext;
}

std::string affine_decryption(std::string ciphertext, int alpha_key,
                              int beta_key) {
    if (ciphertext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(ciphertext);

    if (std::gcd(alpha_key, ALPHABET_LENGTH) != 1) {
        throw std::invalid_argument(
            "Key a must be coprime with the alphabet length (26)");
    }

    int decryption_alpha = inverse_by_mod(alpha_key, ALPHABET_LENGTH);
    std::string plaintext;

    for (char letter : ciphertext) {
        if (ALPHABET.find(letter) != std::string::npos) {
            int y = ALPHABET.find(letter);
            int x = ((decryption_alpha * (y - beta_key)) % ALPHABET_LENGTH +
                     ALPHABET_LENGTH) %
                    ALPHABET_LENGTH;
            plaintext += ALPHABET[x];
        } else {
            plaintext += letter;
        }
    }
    return plaintext;
}

std::string brute_force_affine(std::string text) {
    if (text.empty())
        throw std::invalid_argument("Text must not be empty!!");

    int best_score = 0;
    std::string best_text;
    int best_alpha = 1;
    int best_beta = 0;

    std::vector<int> POSSIBLE_ALPHA = {1,  3,  5,  7,  9,  11,
                                       15, 17, 19, 21, 23, 25};

    for (int alpha : POSSIBLE_ALPHA) {
        for (int beta = 0; beta < 26; beta++) {
            std::string plaintext_try = affine_decryption(text, alpha, beta);
            int score = good_text(plaintext_try);

            if (score > best_score) {
                best_score = score;
                best_text = plaintext_try;
                best_alpha = alpha;
                best_beta = beta;
            }
        }
    }

    std::cout << "Best key: " << best_alpha << ";  " << best_beta << std::endl;
    std::cout << "Readability score: " << best_score << std::endl;
    return best_text;
}
