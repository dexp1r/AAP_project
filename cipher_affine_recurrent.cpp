#include "cipher.h"
#include <iostream>
#include <numeric>
#include <stdexcept>

std::string affine_reccurent_encryption(std::string plaintext, int alpha_key_0,
                                        int beta_key_0, int alpha_key_1,
                                        int beta_key_1) {
    if (plaintext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(plaintext);

    if (std::gcd(alpha_key_0, ALPHABET_LENGTH) != 1 ||
        std::gcd(alpha_key_1, ALPHABET_LENGTH) != 1) {
        throw std::invalid_argument(
            "Each key a must be coprime with the alphabet length (26)");
    }

    plaintext = to_upper(plaintext);
    std::string ciphertext;

    int letter_count = 0;
    for (char c : plaintext) {
        if (ALPHABET.find(c) != std::string::npos)
            letter_count++;
    }

    int plaintext_length = letter_count;
    std::vector<int> alpha_keys(plaintext_length);
    std::vector<int> beta_keys(plaintext_length);

    alpha_keys[0] = alpha_key_0;
    beta_keys[0] = beta_key_0;
    if (plaintext_length > 1) {
        alpha_keys[1] = alpha_key_1;
        beta_keys[1] = beta_key_1;
    }

    for (int i = 2; i < plaintext_length; i++) {
        alpha_keys[i] =
            (alpha_keys[i - 2] * alpha_keys[i - 1]) % ALPHABET_LENGTH;
        beta_keys[i] = (beta_keys[i - 2] + beta_keys[i - 1]) % ALPHABET_LENGTH;

        if (std::gcd(alpha_keys[i], ALPHABET_LENGTH) != 1) {
            throw std::invalid_argument(
                "Each key a must be coprime with the alphabet length (26)");
        }
    }

    int key_pos = 0;
    for (char letter : plaintext) {
        if (ALPHABET.find(letter) != std::string::npos) {
            int x = ALPHABET.find(letter);
            int y = (alpha_keys[key_pos] * x + beta_keys[key_pos]) %
                    ALPHABET_LENGTH;
            ciphertext += ALPHABET[y];
            key_pos++;
        } else {
            ciphertext += letter;
        }
    }
    return ciphertext;
}

std::string affine_reccurent_decryption(std::string ciphertext, int alpha_key_0,
                                        int beta_key_0, int alpha_key_1,
                                        int beta_key_1) {
    if (ciphertext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(ciphertext);

    if (std::gcd(alpha_key_0, ALPHABET_LENGTH) != 1 ||
        std::gcd(alpha_key_1, ALPHABET_LENGTH) != 1) {
        throw std::invalid_argument(
            "Each key a must be coprime with the alphabet length (26)");
    }

    std::string plaintext;

    int letter_count = 0;
    for (char c : ciphertext) {
        if (ALPHABET.find(c) != std::string::npos)
            letter_count++;
    }

    int ciphertext_length = letter_count;
    std::vector<int> alpha_keys(ciphertext_length);
    std::vector<int> beta_keys(ciphertext_length);

    alpha_keys[0] = alpha_key_0;
    beta_keys[0] = beta_key_0;
    if (ciphertext_length > 1) {
        alpha_keys[1] = alpha_key_1;
        beta_keys[1] = beta_key_1;
    }

    for (int i = 2; i < ciphertext_length; i++) {
        alpha_keys[i] =
            (alpha_keys[i - 2] * alpha_keys[i - 1]) % ALPHABET_LENGTH;
        beta_keys[i] = (beta_keys[i - 2] + beta_keys[i - 1]) % ALPHABET_LENGTH;

        if (std::gcd(alpha_keys[i], ALPHABET_LENGTH) != 1) {
            throw std::invalid_argument(
                "Each key a must be coprime with the alphabet length (26)");
        }
    }

    int key_pos = 0;
    for (char letter : ciphertext) {
        if (ALPHABET.find(letter) != std::string::npos) {
            int y = ALPHABET.find(letter);
            int x = ((inverse_by_mod(alpha_keys[key_pos], ALPHABET_LENGTH) *
                      (y - beta_keys[key_pos])) %
                         ALPHABET_LENGTH +
                     ALPHABET_LENGTH) %
                    ALPHABET_LENGTH;
            plaintext += ALPHABET[x];
            key_pos++;
        } else {
            plaintext += letter;
        }
    }
    return plaintext;
}

std::string brute_force_affine_reccurent(std::string text) {
    if (text.empty())
        throw std::invalid_argument("Text must not be empty!!");

    int best_score = 0;
    std::string best_text;
    int best_alpha_0 = 1;
    int best_beta_0 = 0;
    int best_alpha_1 = 1;
    int best_beta_1 = 0;

    std::vector<int> POSSIBLE_ALPHA = {1,  3,  5,  7,  9,  11,
                                       15, 17, 19, 21, 23, 25};

    for (int alpha0 : POSSIBLE_ALPHA) {
        for (int beta0 = 0; beta0 < 26; beta0++) {
            for (int alpha1 : POSSIBLE_ALPHA) {
                for (int beta1 = 0; beta1 < 26; beta1++) {
                    std::string plaintext_try = affine_reccurent_decryption(
                        text, alpha0, beta0, alpha1, beta1);
                    int score = good_text(plaintext_try);

                    if (score > best_score) {
                        best_score = score;
                        best_text = plaintext_try;
                        best_alpha_0 = alpha0;
                        best_beta_0 = beta0;
                        best_alpha_1 = alpha1;
                        best_beta_1 = beta1;
                    }
                }
            }
        }
    }

    std::cout << "Best key: " << best_alpha_0 << ";  " << best_beta_0 << ";  "
              << best_alpha_1 << ";  " << best_beta_1 << std::endl;
    std::cout << "Readability score: " << best_score << std::endl;
    return best_text;
}
