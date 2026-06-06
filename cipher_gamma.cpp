#include "cipher.h"
#include <iostream>
#include <stdexcept>

std::string encryption_with_random_gamma(std::string plaintext) {
    if (plaintext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(plaintext);

    plaintext = to_upper(plaintext);
    int letter_count = 0;
    for (char c : plaintext) {
        if (ALPHABET.find(c) != std::string::npos) {
            letter_count++;
        }
    }

    std::string gamma = random_gamma(letter_count);
    std::cout << "Generated gamma (save it for decryption): " << gamma
              << std::endl;
    std::vector<int> gamma_index = text_to_index(gamma);

    std::string ciphertext;
    int gamma_pos = 0;

    for (int i = 0; i < (int)plaintext.length(); i++) {
        if (ALPHABET.find(plaintext[i]) != std::string::npos) {
            int p = ALPHABET.find(plaintext[i]);
            char cipherletter =
                ALPHABET[(p + gamma_index[gamma_pos]) % ALPHABET_LENGTH];
            ciphertext += cipherletter;
            gamma_pos++;
        } else {
            ciphertext += plaintext[i];
        }
    }
    return ciphertext;
}

std::string encryption_with_user_gamma(std::string plaintext,
                                       std::string gamma) {
    if (gamma.empty())
        throw std::invalid_argument("Gamma must not be empty!!");
    if (plaintext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    check_is_english(plaintext);
    check_is_english(gamma);

    plaintext = to_upper(plaintext);
    gamma = to_upper(gamma);

    int length_gamma = gamma.length();
    std::vector<int> gamma_index = text_to_index(gamma);

    std::string ciphertext;
    int gamma_pos = 0;

    for (int i = 0; i < (int)plaintext.length(); i++) {
        if (ALPHABET.find(plaintext[i]) != std::string::npos) {
            int p = ALPHABET.find(plaintext[i]);
            char cipherletter =
                ALPHABET[(p + gamma_index[gamma_pos % length_gamma]) %
                         ALPHABET_LENGTH];
            ciphertext += cipherletter;
            gamma_pos++;
        } else {
            ciphertext += plaintext[i];
        }
    }
    return ciphertext;
}

std::string gamma_decryption(std::string ciphertext, std::string gamma) {
    if (gamma.empty()) {
        throw std::invalid_argument("Gamma must not be empty!!");
    }
    if (ciphertext.empty()) {
        throw std::invalid_argument("Text must not be empty!!");
    }
    check_is_english(ciphertext);
    check_is_english(gamma);

    gamma = to_upper(gamma);

    int length_gamma = gamma.length();
    std::vector<int> gamma_index = text_to_index(gamma);

    std::string plaintext;
    int gamma_pos = 0;

    for (int i = 0; i < (int)ciphertext.length(); i++) {
        if (ALPHABET.find(ciphertext[i]) != std::string::npos) {
            int c = ALPHABET.find(ciphertext[i]);
            char plainletter =
                ALPHABET[((c - gamma_index[gamma_pos % length_gamma]) %
                              ALPHABET_LENGTH +
                          ALPHABET_LENGTH) %
                         ALPHABET_LENGTH];
            plaintext += plainletter;
            gamma_pos++;
        } else {
            plaintext += ciphertext[i];
        }
    }
    return plaintext;
}

int gamma_length(std::string ciphertext) {
    if (ciphertext.empty())
        throw std::invalid_argument("Text must not be empty!!");

    int best_length = 1;
    int best_score = 0;

    for (int length = 1; length <= 20; length++) {
        std::vector<std::string> one_position_letters(length);

        // Отдельный счетчик только для букв
        int letter_pos = 0;
        for (int i = 0; i < (int)ciphertext.length(); i++) {
            if (ALPHABET.find(ciphertext[i]) != std::string::npos) {
                one_position_letters[letter_pos % length] += ciphertext[i];
                letter_pos++;
            }
        }

        int score = 0;
        for (int g = 0; g < length; g++) {
            score += good_text(one_position_letters[g]);
        }

        if (score > best_score) {
            best_score = score;
            best_length = length;
        }
    }
    return best_length;
}

int find_gamma_symbol(std::string one_position_letters) {
    std::vector<int> amount_of_each_letter(26, 0);
    int length = one_position_letters.length();

    for (int i = 0; i < length; i++) {
        int index = ALPHABET.find(one_position_letters[i]);
        // Исключаем пробелы
        if (index != std::string::npos) {
            amount_of_each_letter[index]++;
        }
    }

    int max_count = 0;
    int most_often_letter_index = 0;

    for (int i = 0; i < 26; i++) {
        if (amount_of_each_letter[i] > max_count) {
            max_count = amount_of_each_letter[i];
            most_often_letter_index = i;
        }
    }

    int gamma_letter_index = (most_often_letter_index - 4 + 26) % 26;
    return gamma_letter_index;
}

std::string known_plaintext_attack(std::string ciphertext,
                                   std::string known_plaintext) {
    if (ciphertext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    if (known_plaintext.empty())
        throw std::invalid_argument("Text must not be empty!!");
    if (known_plaintext.length() > ciphertext.length())
        throw std::invalid_argument("Plaintext is longer than ciphertext");

    check_is_english(ciphertext);
    check_is_english(known_plaintext);

    ciphertext = to_upper(ciphertext);
    known_plaintext = to_upper(known_plaintext);

    std::string gamma_part;
    int length = known_plaintext.length();

    for (int i = 0; i < length; i++) {
        if (ALPHABET.find(ciphertext[i]) != std::string::npos &&
            ALPHABET.find(known_plaintext[i]) != std::string::npos) {
            int c = ALPHABET.find(ciphertext[i]);
            int p = ALPHABET.find(known_plaintext[i]);
            int g = (c - p + ALPHABET_LENGTH) % ALPHABET_LENGTH;
            gamma_part += ALPHABET[g];
        }
    }

    std::cout << "Found gamma segment: " << gamma_part << std::endl;

    std::string result = gamma_decryption(ciphertext, gamma_part);

    return result;
}

std::string cryptanalyze_gamma(std::string ciphertext) {
    if (ciphertext.empty())
        throw std::invalid_argument("Text must not be empty!!");

    ciphertext = to_upper(ciphertext);

    int length = gamma_length(ciphertext);
    std::cout << "Gamma length: " << length << std::endl;

    std::vector<std::string> one_position_letters(length);

    int letter_pos = 0;
    for (int i = 0; i < (int)ciphertext.length(); i++) {
        if (ALPHABET.find(ciphertext[i]) != std::string::npos) {
            one_position_letters[letter_pos % length] += ciphertext[i];
            letter_pos++;
        }
    }

    std::string gamma;
    for (int g = 0; g < length; g++) {
        int gamma_num = find_gamma_symbol(one_position_letters[g]);
        gamma += ALPHABET[gamma_num];
    }
    std::cout << "Estimated gamma: " << gamma << std::endl;

    std::string result = gamma_decryption(ciphertext, gamma);
    
    return result;
}
