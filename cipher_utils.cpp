#include "cipher.h"
#include <cctype>
#include <iostream>
#include <random>
#include <stdexcept>

std::string to_upper(std::string text) {
    std::string result;
    for (char letter : text) {
        result += toupper(letter);
    }
    return result;
}

std::string to_lower(std::string text) {
    std::string result;
    for (char letter : text) {
        result += tolower(letter);
    }
    return result;
}

void check_is_english(const std::string &text) {
    for (char letter : text) {
        unsigned char uc = (unsigned char)letter;
        if (uc > 127) {
            throw std::invalid_argument(std::string("Invalid character"));
        }
        if (isalpha(uc) &&
            ALPHABET.find((char)toupper(uc)) == std::string::npos) {
            throw std::invalid_argument(std::string("Invalid character"));
        }
    }
}

std::string random_gamma(int length) {
    // генератор случайности
    std::random_device rd;
    std::mt19937 gen(rd());

    // нам нужно делать гамму, выбирая строку из рандомных чисел
    // от 0 до 25 (индексы букв в строке-алфавите) нужной длины
    std::uniform_int_distribution<int> index(0, 25);

    std::string gamma;
    for (int i = 0; i < length; i++) {
        gamma += ALPHABET[index(gen)];
    }
    return gamma;
}

std::vector<int> text_to_index(std::string text) {
    std::vector<int> index;
    for (char letter : text) {
        int i = ALPHABET.find(letter);
        index.push_back(i);
    }
    return index;
}

std::string index_to_text(std::vector<int> index) {
    std::string text;
    for (int i : index) {
        text += ALPHABET[i];
    }
    return text;
}

int good_text(std::string text) {
    if (text.empty())
        return 0;

    text = to_lower(text);

    int score = 0;

    const std::vector<std::string> COMMON_WORDS_LIST = {
        "the", "and",  "of", "to",  "in", "that", "is", "it",
        "for", "with", "as", "was", "on", "be",   "at"};

    for (const std::string word : COMMON_WORDS_LIST) {
        if (text.find(word) != std::string::npos) {
            score++;
        }
    }

    std::string VOWELS = "aeiou";
    int vowels_count = 0;
    int text_length = 0;

    for (char letter : text) {
        text_length++;

        if (VOWELS.find(letter) != std::string::npos) {
            vowels_count++;
        }
    }

    float vowel_percent = static_cast<float>(vowels_count) / text_length;

    if (vowel_percent > 0.30 && vowel_percent < 0.50) {
        score++;
    }

    return score;
}

std::string input_text(std::string users_str) {
    std::string text;
    std::cout << users_str;
    std::getline(std::cin, text);
    return text;
}

int input_int(std::string users_numb) {
    int numb;
    std::cout << users_numb;
    std::cin >> numb;
    std::cin.ignore();
    return numb;
}
