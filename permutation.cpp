#include "cipher.h"
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#include <string>

namespace {
    // Таблица весов популярных английских биграмм (пар букв)
    // Чем чаще пара встречается в языке, тем выше ее вес.
    const std::map<std::string, double> common_bigrams = {
        {"TH", 3.15}, {"HE", 2.51}, {"AN", 1.72}, {"IN", 1.69}, {"ER", 1.54},
        {"RE", 1.48}, {"ND", 1.43}, {"AT", 1.29}, {"ON", 1.00}, {"NT", 0.98},
        {"HA", 0.93}, {"ES", 0.92}, {"ST", 0.92}, {"EN", 0.91}, {"ED", 0.88},
        {"TO", 0.86}, {"IT", 0.85}, {"OU", 0.83}, {"EA", 0.80}, {"HI", 0.76},
        {"IS", 0.75}, {"OR", 0.75}, {"TI", 0.73}, {"AS", 0.67}, {"TE", 0.67},
        {"ET", 0.65}, {"NG", 0.63}, {"OF", 0.63}, {"AL", 0.62}, {"DE", 0.61},
        {"SE", 0.61}, {"LE", 0.60}, {"SA", 0.59}, {"SI", 0.59}, {"AR", 0.58},
        {"VE", 0.58}, {"RA", 0.57}, {"RO", 0.56}, {"LI", 0.55}, {"NE", 0.54}
    };

    // Анализ текста на основе биграмм
    double analyze_bigrams(const std::string& text) {
        double score = 0.0;
        
        // Выделяем только буквы для чистоты анализа (игнорируем пробелы/знаки)
        std::string clean_text = "";
        for (char c : text) {
            if (ALPHABET.find(c) != std::string::npos) {
                clean_text += c;
            }
        }
        
        if (clean_text.length() < 2) return 0.0;

        // Идем по тексту парами букв и суммируем их "вес"
        for (size_t i = 0; i < clean_text.length() - 1; ++i) {
            std::string bigram = clean_text.substr(i, 2);
            auto it = common_bigrams.find(bigram);
            if (it != common_bigrams.end()) {
                score += it->second;
            }
        }
        // Возвращаем сумму весов. В отличие от старого метода, здесь ЧЕМ БОЛЬШЕ, ТЕМ ЛУЧШЕ!
        return score;
    }

    // Извлекает порядок перестановки из текстового ключа
    std::vector<int> get_permutation(const std::string& key) {
        std::vector<std::pair<char, int>> indexed_key;
        for (size_t i = 0; i < key.length(); i++) {
            indexed_key.push_back({key[i], (int)i});
        }
        std::stable_sort(indexed_key.begin(), indexed_key.end());
        std::vector<int> perm(key.length());
        for (size_t i = 0; i < indexed_key.size(); i++) {
            perm[indexed_key[i].second] = i;
        }
        return perm;
    }
}

std::string permutation_encryption(std::string plaintext, std::string key) {
    if (key.empty()) throw std::invalid_argument("Key cannot be empty.");
    plaintext = to_upper(plaintext);
    key = to_upper(key);

    std::vector<int> perm = get_permutation(key);
    int block_size = perm.size();

    // Дополняем текст, если его длина не кратна размеру блока (добиваем буквой A)
    while (plaintext.length() % block_size != 0) {
        plaintext += ALPHABET[0]; 
    }

    std::string cipher = plaintext;
    for (size_t i = 0; i < plaintext.length(); i += block_size) {
        for (int j = 0; j < block_size; j++) {
            cipher[i + perm[j]] = plaintext[i + j];
        }
    }
    return cipher;
}

std::string permutation_decryption(std::string ciphertext, std::string key) {
    if (key.empty()) throw std::invalid_argument("Key cannot be empty.");
    ciphertext = to_upper(ciphertext);
    key = to_upper(key);

    std::vector<int> perm = get_permutation(key);
    int block_size = perm.size();

    if (ciphertext.length() % block_size != 0) {
        throw std::invalid_argument("Ciphertext length must be a multiple of the key length.");
    }

    // Создаем обратную перестановку для расшифровки
    std::vector<int> inv_perm(block_size);
    for (int i = 0; i < block_size; i++) inv_perm[perm[i]] = i;

    std::string plain = ciphertext;
    for (size_t i = 0; i < ciphertext.length(); i += block_size) {
        for (int j = 0; j < block_size; j++) {
            plain[i + inv_perm[j]] = ciphertext[i + j];
        }
    }
    return plain;
}

std::string permutation_cryptanalyze(std::string ciphertext) {
    if (ciphertext.empty()) throw std::invalid_argument("Ciphertext cannot be empty.");
    ciphertext = to_upper(ciphertext);

    std::string best_text = "";
    double best_score = -1.0; // Стартуем с минуса, так как ищем максимальный счет
    
    // Перебор длин блоков. 8! = 40320 комбинаций. 
    // Если ключ был длиннее 8, будет долго, но для стандартных CTF-тасков 8 хватает за глаза.
    int max_block = std::min((int)ciphertext.length(), 8);

    for (int bs = 2; bs <= max_block; ++bs) {
        // Пропускаем размер блока, если текст на него не делится нацело
        if (ciphertext.length() % bs != 0) continue;

        std::vector<int> perm(bs);
        std::iota(perm.begin(), perm.end(), 0); // Заполняем 0, 1, 2 ... bs-1

        // Генерируем все возможные перестановки (брутфорс факториала)
        do {
            std::vector<int> inv_perm(bs);
            for (int i = 0; i < bs; i++) inv_perm[perm[i]] = i;

            std::string plain = ciphertext;
            for (size_t i = 0; i < ciphertext.length(); i += bs) {
                for (int j = 0; j < bs; j++) {
                    plain[i + inv_perm[j]] = ciphertext[i + j];
                }
            }

            // Оцениваем расшифрованный вариант
            double score = analyze_bigrams(plain);
            if (score > best_score) {
                best_score = score;
                best_text = plain;
            }
        } while (std::next_permutation(perm.begin(), perm.end()));
    }
    
    if (best_text.empty()) {
        throw std::invalid_argument("Failed to find a suitable block size.");
    }
    return best_text;
}
