#include "cipher.h"
#include <stdexcept>
#include <map>
#include <algorithm>
#include <iostream>

namespace {
    // Таблица частотностей английского языка для криптоанализа
    const std::map<char, double> freq_en = {
        {'A', 0.0817}, {'B', 0.0149}, {'C', 0.0278}, {'D', 0.0425}, {'E', 0.1270},
        {'F', 0.0223}, {'G', 0.0202}, {'H', 0.0609}, {'I', 0.0697}, {'J', 0.0015},
        {'K', 0.0077}, {'L', 0.0403}, {'M', 0.0241}, {'N', 0.0675}, {'O', 0.0751},
        {'P', 0.0193}, {'Q', 0.0010}, {'R', 0.0599}, {'S', 0.0633}, {'T', 0.0906},
        {'U', 0.0276}, {'V', 0.0098}, {'W', 0.0236}, {'X', 0.0015}, {'Y', 0.0197},
        {'Z', 0.0007}
    };

    // Оценка текста методом наименьших квадратов
    double analyze_text(const std::string& text) {
        std::map<char, double> count;
        for (char c : ALPHABET) count[c] = 0.0;

        int total = 0;
        for (char ch : text) {
            if (ALPHABET.find(ch) != std::string::npos) {
                count[ch]++;
                total++;
            }
        }
        if (total == 0) return 1e9;

        for (auto& pair : count) pair.second /= total;

        double score = 0;
        for (char c : ALPHABET) {
            double diff = count[c] - freq_en.at(c);
            score += diff * diff;
        }
        return score;
    }
}

std::string vigenere_encryption(std::string plaintext, std::string key, int mode) {
    if (key.empty()) throw std::invalid_argument("Key cannot be empty.");
    
    plaintext = to_upper(plaintext);
    key = to_upper(key);
    check_is_english(key); // Ключ должен состоять только из букв

    std::string cipher = "";
    std::string current_key = key;
    size_t key_ind = 0;

    for (size_t i = 0; i < plaintext.length(); i++) {
        char p_char = plaintext[i];
        size_t p_pos = ALPHABET.find(p_char);

        if (p_pos == std::string::npos) {
            cipher += p_char; 
            continue;
        }

        
        char k_char = (mode == 1) ? current_key[key_ind % current_key.length()] : current_key[0];
        size_t k_pos = ALPHABET.find(k_char);

        
        char c_char = ALPHABET[(p_pos + k_pos) % ALPHABET_LENGTH];
        cipher += c_char;

        
        if (mode == 2) current_key = std::string(1, p_char);
        if (mode == 3) current_key = std::string(1, c_char);
        
        
        if (mode == 1) key_ind++;
    }
    return cipher;
}

std::string vigenere_decryption(std::string ciphertext, std::string key, int mode) {
    if (key.empty()) throw std::invalid_argument("Key cannot be empty.");
    
    ciphertext = to_upper(ciphertext);
    key = to_upper(key);
    check_is_english(key);

    std::string plain = "";
    std::string current_key = key;
    size_t key_ind = 0;

    for (size_t i = 0; i < ciphertext.length(); i++) {
        char c_char = ciphertext[i];
        size_t c_pos = ALPHABET.find(c_char);

        if (c_pos == std::string::npos) {
            plain += c_char; 
            continue;
        }

        char k_char = (mode == 1) ? current_key[key_ind % current_key.length()] : current_key[0];
        size_t k_pos = ALPHABET.find(k_char);

        int val = static_cast<int>(c_pos) - static_cast<int>(k_pos);
        if (val < 0) val += ALPHABET_LENGTH;
        
        char p_char = ALPHABET[val];
        plain += p_char;

        if (mode == 2) current_key = std::string(1, p_char);
        if (mode == 3) current_key = std::string(1, c_char);
        if (mode == 1) key_ind++;
    }
    return plain;
}
std::string vigenere_cryptanalyze(std::string ciphertext, int mode) {
    if (ciphertext.empty()) throw std::invalid_argument("Ciphertext cannot be empty.");
    ciphertext = to_upper(ciphertext);
    
    std::string best_text = "";
    double best_score = 1e9;

    if (mode == 2 || mode == 3) {
        // Для самоключей просто перебираем стартовую букву
        for (char k : ALPHABET) {
            std::string candidate_key(1, k);
            std::string plain = vigenere_decryption(ciphertext, candidate_key, mode);
            double score = analyze_text(plain);
            if (score < best_score) {
                best_score = score;
                best_text = plain;
            }
        }
    } else if (mode == 1) {
        // Очищаем текст от пунктуации ТОЛЬКО для этапа поиска длины и состава ключа
        std::string clean_cipher = "";
        for (char c : ciphertext) {
            if (ALPHABET.find(c) != std::string::npos) {
                clean_cipher += c;
            }
        }

        int max_k_len = std::min(10, (int)clean_cipher.length() / 2);
        if (max_k_len < 1) max_k_len = 1;

        // Ищем ключ по очищенному тексту
        for (int k_len = 1; k_len <= max_k_len; ++k_len) {
            std::string guessed_key = "";

            for (int col = 0; col < k_len; ++col) {
                double best_col_score = 1e9;
                char best_char = ALPHABET[0];

                for (char k : ALPHABET) {
                    std::string col_text = "";
                    for (size_t i = col; i < clean_cipher.length(); i += k_len) {
                        int val = static_cast<int>(ALPHABET.find(clean_cipher[i])) - static_cast<int>(ALPHABET.find(k));
                        if (val < 0) val += ALPHABET_LENGTH;
                        col_text += ALPHABET[val];
                    }
                    double score = analyze_text(col_text);
                    if (score < best_col_score) {
                        best_col_score = score;
                        best_char = k;
                    }
                }
                guessed_key += best_char;
            }

            // Применяем найденный ключ к ИСХОДНОМУ тексту (с сохранением знаков препинания)
            std::string plain = vigenere_decryption(ciphertext, guessed_key, 1);
            double total_score = analyze_text(plain);
            if (total_score < best_score) {
                best_score = total_score;
                best_text = plain;
            }
        }
    }
    return best_text;
}
