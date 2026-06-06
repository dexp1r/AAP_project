#include <cctype>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cipher.h"
#include "crypto_utils.hpp"

// ── Надёжный ввод пункта меню
// ───────────────────────────────────────────────── Читает целую строку; если
// введено не целое число или число вне диапазона [min_val, max_val] — выводит
// сообщение об ошибке и просит ввести снова.
static int ReadMenuChoice(int min_val, int max_val) {
  while (true) {
    std::cout << "Choice: ";
    std::string line;
    if (!std::getline(std::cin, line)) return min_val;  // EOF
    std::istringstream ss(line);
    int val = 0;
    char leftover = 0;
    if ((ss >> val) && !(ss >> leftover)) {
      if (val >= min_val && val <= max_val) return val;
      std::cout << "  Please enter a number from " << min_val << " to "
                << max_val << ".\n";
    } else {
      std::cout << "  Invalid input, please enter a number from " << min_val
                << " to " << max_val << ".\n";
    }
  }
}

// ── Вспомогательные функции ввода (для параметров шифров)
// ─────────────────────

static std::string ReadLine(const std::string& prompt) {
  std::cout << prompt;
  std::string line;
  std::getline(std::cin, line);
  return line;
}

static int ReadInt(const std::string& prompt) {
  while (true) {
    std::string line = ReadLine(prompt);
    std::istringstream ss(line);
    int v = 0;
    char leftover = 0;
    if ((ss >> v) && !(ss >> leftover)) return v;
    std::cout << "  Invalid input — please enter an integer.\n";
  }
}

static std::vector<int> ReadIntList(const std::string& prompt, int count) {
  while (true) {
    std::string line = ReadLine(prompt);
    std::istringstream ss(line);
    std::vector<int> vals;
    int v = 0;
    while (ss >> v) vals.push_back(v);
    if (static_cast<int>(vals.size()) == count) return vals;
    std::cout << "  Expected " << count << " integers, got " << vals.size()
              << ". Try again.\n";
  }
}

// ── Форматирование вывода
// ─────────────────────────────────────────────────────

static std::string RestoreStructure(const std::string& original,
                                    const std::string& letters_out) {
  std::string result;
  result.reserve(original.size() + letters_out.size());
  std::size_t pos = 0;
  for (char c : original) {
    if (isalpha(static_cast<unsigned char>(c))) {
      if (pos < letters_out.size()) result.push_back(letters_out[pos++]);
    } else {
      result.push_back(c);
    }
  }
  while (pos < letters_out.size()) result.push_back(letters_out[pos++]);
  return result;
}

static void menu_substitution() {
  int choice = -1;
  while (choice != 0) {
    std::cout
        << "\n-Simple Substitution Cipher-\n"
        << "[1] Encrypt\n[2] Decrypt\n[3] Break (cryptanalysis)\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1) {
        std::string text = ReadLine("Plaintext: ");
        std::string key = ReadLine("Cipher alphabet (26 letters): ");
        std::string ct = simple_substitution_encrypt(text, key);
        std::cout << "Result: " << RestoreStructure(text, ct) << "\n";
      } else if (choice == 2) {
        std::string text = ReadLine("Ciphertext: ");
        std::string key = ReadLine("Cipher alphabet (26 letters): ");
        std::string pt = simple_substitution_decrypt(text, key);
        std::cout << "Result: " << RestoreStructure(text, pt) << "\n";
      } else if (choice == 3) {
        std::string text = ReadLine("Ciphertext: ");
        std::string pt = simple_substitution_break(text);
        std::cout << "Result: " << RestoreStructure(text, pt) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( : " << e.what() << "\n";
    }
  }
}

static void menu_hill() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Hill Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Break (brute-force, 2x2 "
                 "only)\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1 || choice == 2) {
        int n = ReadInt("Matrix order n (block size): ");
        std::vector<int> kv = ReadIntList("Enter " + std::to_string(n * n) +
                                              " matrix elements (row by row): ",
                                          n * n);
        std::string text =
            ReadLine(choice == 1 ? "Plaintext: " : "Ciphertext: ");
        std::string res = (choice == 1) ? hill_encrypt(text, kv, n)
                                        : hill_decrypt(text, kv, n);
        std::cout << (choice == 1 ? "Ciphertext" : "Plaintext") << ": "
                  << RestoreStructure(text, res) << "\n";
      } else if (choice == 3) {
        std::cout << "Note: brute-force is supported only for a 2x2 key.\n";
        std::string text = ReadLine("Ciphertext: ");
        std::string pt = hill_break(text);
        std::cout << "Result: " << RestoreStructure(text, pt) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( : " << e.what() << "\n";
    }
  }
}

static void menu_recurrent_hill() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Recurrent Hill Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Break (brute-force, 2x2 "
                 "only)\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1 || choice == 2) {
        int m = ReadInt("Number of key matrices: ");
        int n = ReadInt("Matrix order n (same for all matrices): ");
        std::vector<std::vector<int>> keys_vals;
        for (int j = 0; j < m; ++j) {
          keys_vals.push_back(ReadIntList(
              "K" + std::to_string(j + 1) + " - Enter " +
                  std::to_string(n * n) + " elements (row by row): ",
              n * n));
        }
        std::string text =
            ReadLine(choice == 1 ? "Plaintext: " : "Ciphertext: ");
        std::string res = (choice == 1)
                              ? recurrent_hill_encrypt(text, keys_vals, n)
                              : recurrent_hill_decrypt(text, keys_vals, n);
        std::cout << (choice == 1 ? "Ciphertext" : "Plaintext") << ": "
                  << RestoreStructure(text, res) << "\n";
      } else if (choice == 3) {
        std::cout << "Note: brute-force is supported only for 2x2 matrices.\n";
        std::string text = ReadLine("Ciphertext: ");
        int nk = ReadInt("Number of key matrices to recover (period): ");
        std::string pt = recurrent_hill_break(text, nk);
        std::cout << "Result: " << RestoreStructure(text, pt) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( : " << e.what() << "\n";
    }
  }
}

static void menu_affine() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Affine Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Cryptanalysis\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1) {
        std::string text = input_text("Enter your text: ");
        int a = input_int("Enter key a: ");
        int b = input_int("Enter key b: ");
        std::cout << "Result: " << affine_encryption(text, a, b) << "\n";
      } else if (choice == 2) {
        std::string text = input_text("Enter your text: ");
        int a = input_int("Enter key a: ");
        int b = input_int("Enter key b: ");
        std::cout << "Result: " << affine_decryption(text, a, b) << "\n";
      } else if (choice == 3) {
        std::string text = input_text("Enter your ciphertext: ");
        std::cout << "Result: " << brute_force_affine(text) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

static void menu_affine_reccurent() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Affine Recurrent Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Cryptanalysis\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1) {
        std::string text = input_text("Enter your text: ");
        int a0 = input_int("Enter key a0: "), b0 = input_int("Enter key b0: ");
        int a1 = input_int("Enter key a1: "), b1 = input_int("Enter key b1: ");
        std::cout << "Result: "
                  << affine_reccurent_encryption(text, a0, b0, a1, b1) << "\n";
      } else if (choice == 2) {
        std::string text = input_text("Enter your ciphertext: ");
        int a0 = input_int("Enter key a0: "), b0 = input_int("Enter key b0: ");
        int a1 = input_int("Enter key a1: "), b1 = input_int("Enter key b1: ");
        std::cout << "Result: "
                  << affine_reccurent_decryption(text, a0, b0, a1, b1) << "\n";
      } else if (choice == 3) {
        std::string text = input_text("Enter your ciphertext: ");
        std::cout << "Result: " << brute_force_affine_reccurent(text) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

static void menu_gamma() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Gamma Cipher-\n"
              << "[1] Encrypt (random gamma)\n[2] Encrypt (your gamma)\n"
              << "[3] Decrypt\n[4] Cryptanalysis (frequency)\n"
              << "[5] Cryptanalysis (known plaintext)\n[0] Back\n";
    choice = ReadMenuChoice(0, 5);
    try {
      if (choice == 1) {
        std::string text = input_text("Enter your text: ");
        std::cout << "Result: " << encryption_with_random_gamma(text) << "\n";
      } else if (choice == 2) {
        std::string text = input_text("Enter your text: ");
        std::string gamma = input_text("Gamma: ");
        std::cout << "Result: " << encryption_with_user_gamma(text, gamma)
                  << "\n";
      } else if (choice == 3) {
        std::string text = input_text("Enter your ciphertext: ");
        std::string gamma = input_text("Gamma: ");
        std::cout << "Result: " << gamma_decryption(text, gamma) << "\n";
      } else if (choice == 4) {
        std::string text = input_text("Enter your ciphertext: ");
        std::cout << "Result: " << cryptanalyze_gamma(text) << "\n";
      } else if (choice == 5) {
        std::string text = input_text("Enter your ciphertext: ");
        std::string known = input_text("Known plaintext fragment: ");
        std::cout << "Result: " << known_plaintext_attack(text, known) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

static void menu_vigenere() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Vigenere Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Cryptanalysis\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice >= 1 && choice <= 3) {
        std::cout << "Select mode:\n"
                  << "  [1] Repeat short keyword\n"
                  << "  [2] Plaintext autokey\n"
                  << "  [3] Ciphertext autokey\n";
        int mode = ReadMenuChoice(1, 3);
        if (choice == 1) {
          std::string text = input_text("Enter your text: ");
          std::string key = input_text("Enter keyword: ");
          std::cout << "Result: " << vigenere_encryption(text, key, mode)
                    << "\n";
        } else if (choice == 2) {
          std::string text = input_text("Enter your ciphertext: ");
          std::string key = input_text("Enter keyword: ");
          std::cout << "Result: " << vigenere_decryption(text, key, mode)
                    << "\n";
        } else {
          std::string text = input_text("Enter your ciphertext: ");
          std::cout << "Result: " << vigenere_cryptanalyze(text, mode) << "\n";
        }
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

static void menu_vernam() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Vernam Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Cryptanalysis\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1) {
        std::string text = input_text("Enter your text: ");
        std::string key = input_text("Enter key (same length as text): ");
        std::cout << "Result: " << vernam_encryption(text, key) << "\n";
      } else if (choice == 2) {
        std::string text = input_text("Enter your ciphertext: ");
        std::string key = input_text("Enter key (same length as text): ");
        std::cout << "Result: " << vernam_decryption(text, key) << "\n";
      } else if (choice == 3) {
        std::cout << "Error :( : Vernam cipher possesses perfect secrecy."
                     " Cryptanalysis without key is impossible.\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

static void menu_permutation() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\n-Block Permutation Cipher-\n"
              << "[1] Encrypt\n[2] Decrypt\n[3] Cryptanalysis\n[0] Back\n";
    choice = ReadMenuChoice(0, 3);
    try {
      if (choice == 1) {
        std::string text = input_text("Enter your text: ");
        std::string key = input_text("Enter text key (e.g. 'CAB'): ");
        std::cout << "Result: " << permutation_encryption(text, key) << "\n";
      } else if (choice == 2) {
        std::string text = input_text("Enter your ciphertext: ");
        std::string key = input_text("Enter text key: ");
        std::cout << "Result: " << permutation_decryption(text, key) << "\n";
      } else if (choice == 3) {
        std::string text = input_text("Enter your ciphertext: ");
        std::cout << "Result: " << permutation_cryptanalyze(text) << "\n";
      }
    } catch (const std::invalid_argument& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
}

// ── Главное меню
// ──────────────────────────────────────────────────────────────

int main() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\nMenu\n"
              << "1. Simple Substitution Cipher\n"
              << "2. Hill Cipher\n"
              << "3. Recurrent Hill Cipher\n"
              << "4. Affine Cipher\n"
              << "5. Affine Recurrent Cipher\n"
              << "6. Gamma Cipher\n"
              << "7. Vigenere Cipher\n"
              << "8. Vernam Cipher\n"
              << "9. Block Permutation Cipher\n"
              << "0. Exit\n";
    choice = ReadMenuChoice(0, 9);
    try {
      if (choice == 1)
        menu_substitution();
      else if (choice == 2)
        menu_hill();
      else if (choice == 3)
        menu_recurrent_hill();
      else if (choice == 4)
        menu_affine();
      else if (choice == 5)
        menu_affine_reccurent();
      else if (choice == 6)
        menu_gamma();
      else if (choice == 7)
        menu_vigenere();
      else if (choice == 8)
        menu_vernam();
      else if (choice == 9)
        menu_permutation();
    } catch (const std::exception& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
  std::cout << "Goodbye!\nPress Enter to exit...";
  std::string dummy;
  std::getline(std::cin, dummy);
  return 0;
}
