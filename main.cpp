#include <cctype>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cipher.h"
#include "crypto_utils.hpp"

static int ReadMenuChoice(int min_val, int max_val) {
  while (true) {
    std::cout << "Choice: ";
    std::string line;
    if (!std::getline(std::cin, line)) return min_val;
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

static void menu_help() {
  int choice = -1;
  while (choice != 0) {
    std::cout << std::endl << "Help" << std::endl;
    std::cout << "1.  Simple Substitution Cipher" << std::endl;
    std::cout << "2.  Hill Cipher" << std::endl;
    std::cout << "3.  Recurrent Hill Cipher" << std::endl;
    std::cout << "4.  Affine Cipher" << std::endl;
    std::cout << "5.  Affine Recurrent Cipher" << std::endl;
    std::cout << "6.  Gamma Cipher" << std::endl;
    std::cout << "7.  Vigenere Cipher" << std::endl;
    std::cout << "8.  Vernam Cipher" << std::endl;
    std::cout << "9.  Block Permutation Cipher" << std::endl;
    std::cout << "0.  Back" << std::endl;
    choice = ReadMenuChoice(0, 9);

    if (choice == 1) {
      std::cout << R"(
SIMPLE SUBSTITUTION CIPHER

Description:
Each letter of the plaintext is replaced by a fixed different letter.
Key: a permutation of 26 letters (e.g. QWERTYUIOPASDFGHJKLZXCVBNM).
  A->Q, B->W, C->E, ...
Encryption:  ciphertext[i] = key[plaintext[i]]
Decryption:  inverse substitution table

Cryptanalysis (hill-climbing + trigrams):
  1. Initial guess: most frequent ciphertext letter -> E, next -> T, etc.
  2. Swap letter pairs, keep the swap if trigram score improves.
  3. Repeat 60 times from random starting points, take the best result.
  Needs 100+ letters for reliable recovery.

Security:
  Key space: 26! ~ 4x10^26 - brute-force is impossible.
  Completely broken by frequency analysis on sufficiently long text.
      )" << std::endl;

    } else if (choice == 2) {
      std::cout << R"(
HILL CIPHER

Description:
Block cipher: plaintext is split into n-letter blocks,
each block is multiplied by an n*n key matrix modulo 26.
Encryption:  c = K * p  (mod 26)
Decryption:  p = K^-1 * c  (mod 26)

Key requirements:
  Matrix must be square and invertible mod 26: gcd(det(K), 26) = 1.
  Inverse computed via adjugate: K^-1 = det^-1 * adj(K) mod 26.

Padding: if text length is not a multiple of n, letter X is appended.
  X is stripped automatically after decryption.
Supported block sizes for encrypt/decrypt: 1-8.

Cryptanalysis (2x2 only):
  Brute-forces all 157248 invertible 2x2 matrices mod 26.
  Each candidate decryption is scored by trigram frequency.
  Larger block sizes are computationally infeasible to brute-force.
      )" << std::endl;

    } else if (choice == 3) {
      std::cout << R"(
RECURRENT HILL CIPHER

Description:
Extension of Hill cipher with m key matrices K1, K2, ..., Km.
Block i (1-based) is encrypted with K_((i-1 mod m)+1) - matrices cycle.
  Block 0 -> K1, Block 1 -> K2, ..., Block m -> K1, ...

Cryptanalysis (2x2 only):
  Blocks 0, m, 2m, ... share K1 -> brute-force K1 from those blocks only.
  Blocks 1, m+1, 2m+1, ... share K2 -> brute-force K2 independently.
  Total candidates: m * 157248 (linear, NOT exponential).
  Needs ~40+ ciphertext letters per matrix for reliable recovery.
      )" << std::endl;

    } else if (choice == 4) {
      std::cout << R"(
AFFINE CIPHER

Description:
Each letter of the plaintext is encrypted by the formula:
Encryption:  y = (a * x + b) mod 26
Decryption: x = a_inv * (y - b) mod 26
where x - plaintext letter index (A=0, B=1, ..., Z=25),
y - ciphertext letter index,
a, b - key pair,
a_inv - modular inverse of a modulo 26.

Important!
    a must be coprime with 26, otherwise decryption is ambiguous.
    Valid values of a: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
    b - any number from 0 to 25 (larger values will be reduced mod 26).

Security:
    Key space: 12 * 26 = 312 - easily exhausted by brute-force.
    Vulnerable to frequency analysis: the most frequent ciphertext letter likely corresponds to E.
    Knowing 2 plaintext-ciphertext letter pairs, the key is recovered immediately via a system of equations.
        )" << std::endl;

    } else if (choice == 5) {
      std::cout << R"(
AFFINE RECURRENT CIPHER

Description:
Each letter has its own key computed from previous keys.
Two initial pairs are provided: (a0, b0) and (a1, b1).
Subsequent keys are computed as:
    a_i = (a_{i-2} * a_{i-1}) mod 26
    b_i = (b_{i-2} + b_{i-1}) mod 26
Encryption of each letter: y = (a_i * x + b_i) mod 26
Decryption of each letter: x = a_i_inv * (y - b_i) mod 26

Important!
    a0 and a1 must be coprime with 26.
    Valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25

Security:
    Frequency analysis is harder - each letter is encrypted differently.
    However, keys follow a fixed recurrence, and the number of initial pairs is finite, so brute-force is possible.
    With a known plaintext fragment, the initial keys can be recovered and the full message decrypted.
        )" << std::endl;

    } else if (choice == 6) {
      std::cout << R"(
GAMMA CIPHER

How it works:
A gamma (key sequence) is applied to the plaintext:
Encryption:  y_i = (x_i + gamma_i) mod 26
Decryption: x_i = (y_i - gamma_i + 26) mod 26
The gamma repeats cyclically if it is shorter than the text.

Modes:
Random gamma - the program generates a gamma equal to the text length.
    Save the gamma. Decryption is impossible without the key.
Custom gamma - your own key sequence.

Security:
    A short gamma is vulnerable: identical text fragments at the same positions produce identical ciphertext.
    The gamma length can be found from repeat distances (Kasiski test), then frequency analysis is applied per position.
    A long random gamma is significantly more secure.
    With a known plaintext fragment, the gamma is recovered directly: gamma_i = (y_i - x_i + 26) mod 26.
        )" << std::endl;

    } else if (choice == 7) {
      std::cout << R"(
VIGENERE CIPHER

Description:
  Uses a keyword to shift letters based on the Vigenere square.
  Supports 3 modes:
  1. Repeat short keyword.
  2. Plaintext autokey (key is padded with plaintext).
  3. Ciphertext autokey (key is padded with ciphertext).

Security:
  Vulnerable to Kasiski examination and frequency analysis.
  Autokey modes are slightly stronger but can still be broken.
)" << std::endl;

    } else if (choice == 8) {
      std::cout << R"(
VERNAM CIPHER (One-Time Pad)

Description:
  Modular addition of plaintext and a random key of the SAME length.
  
Security:
  Possesses PERFECT SECRECY (absolute cryptographic strength) if the key is truly random and never reused.
  Brute-force yields all possible plaintexts with equal probability.
)" << std::endl;

    } else if (choice == 9) {
      std::cout << R"(
BLOCK PERMUTATION CIPHER

Description:
  Divides text into blocks and scrambles the letters within each block.
  The permutation order is derived alphabetically from a text keyword.
  Example: Key "CAB" -> Order: 2, 0, 1.

Security:
  Vulnerable to frequency analysis of n-grams. Brute-forcing block sizes and permutations is effective for small keys.
)" << std::endl;

    } else if (choice != 0) {
      std::cout << "Unknown command..." << std::endl;
    }
  }
}


int main() {
  int choice = -1;
  while (choice != 0) {
    std::cout << "\nMenu\n"
              << "1.  Simple Substitution Cipher\n"
              << "2.  Hill Cipher\n"
              << "3.  Recurrent Hill Cipher\n"
              << "4.  Affine Cipher\n"
              << "5.  Affine Recurrent Cipher\n"
              << "6.  Gamma Cipher\n"
              << "7.  Vigenere Cipher\n"
              << "8.  Vernam Cipher\n"
              << "9.  Block Permutation Cipher\n"
              << "10. Help\n"
              << "0.  Exit\n";
    choice = ReadMenuChoice(0, 10);
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
      else if (choice == 10)
        menu_help();
    } catch (const std::exception& e) {
      std::cerr << "Error :( :  " << e.what() << "\n";
    }
  }
  std::cout << "Goodbye!\nPress Enter to exit...";
  std::string dummy;
  std::getline(std::cin, dummy);
  return 0;
}
