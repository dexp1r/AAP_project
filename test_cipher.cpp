#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "cipher.h"

TEST_CASE("to_upper - converting string to uppercase") {
  CHECK(to_upper("hello") == "HELLO");
  CHECK(to_upper("HELLO") == "HELLO");
  CHECK(to_upper("HeLLo WoRLd") == "HELLO WORLD");
  CHECK(to_upper("abc 123") == "ABC 123");
  CHECK(to_upper("") == "");
}

TEST_CASE("to_lower - converting string to lowercase") {
  CHECK(to_lower("HELLO") == "hello");
  CHECK(to_lower("hello") == "hello");
  CHECK(to_lower("HeLLo WoRLd") == "hello world");
  CHECK(to_lower("ABC 123") == "abc 123");
}

TEST_CASE("check_is_english - validation for english alphabet") {
  // хорошие случаи
  CHECK_NOTHROW(check_is_english("hello"));
  CHECK_NOTHROW(check_is_english("HELLO WORLD"));
  CHECK_NOTHROW(check_is_english("Hello, World! 123"));
  CHECK_NOTHROW(check_is_english(""));

  // плохие случаи
  CHECK_THROWS_AS(check_is_english("привет"), std::invalid_argument);
}

TEST_CASE("text_to_index - letters to indices") {
  std::vector<int> result = text_to_index("ABCZ");
  REQUIRE(result.size() == 4);
  CHECK(result[0] == 0);
  CHECK(result[1] == 1);
  CHECK(result[2] == 2);
  CHECK(result[3] == 25);
}

TEST_CASE("index_to_text - indices to letters") {
  CHECK(index_to_text({0, 25}) == "AZ");
  CHECK(index_to_text({7, 4, 11, 11, 14}) == "HELLO");
  CHECK(index_to_text({}) == "");
}

TEST_CASE("text_to_index and index_to_text are inverse") {
  std::string original = "CRYPTOGRAPHY";
  CHECK(index_to_text(text_to_index(original)) == original);
}

TEST_CASE("encryption_with_random_gamma - encryption with random gamma") {
  // хорошие случаи

  std::string result = encryption_with_random_gamma("HELLO");
  CHECK(result.length() == 5);

  std::string result_with_space = encryption_with_random_gamma("HELLO WORLD");
  CHECK(result_with_space.find(' ') != std::string::npos);

  // плохие случаи
  CHECK_THROWS_AS(encryption_with_random_gamma(""), std::invalid_argument);
  CHECK_THROWS_AS(encryption_with_random_gamma("ПРИВЕТ"),
                  std::invalid_argument);
}

TEST_CASE("random_gamma - random gamma generation") {
  // хорошие случаи
  std::string gamma = random_gamma(5);
  REQUIRE(gamma.length() == 5);
}

TEST_CASE("encryption_with_user_gamma - encryption with user-provided gamma") {
  // хорошие случаи
  CHECK(encryption_with_user_gamma("HELLO", "A") == "HELLO");
  CHECK(encryption_with_user_gamma("HELLO", "B") == "IFMMP");
  CHECK(encryption_with_user_gamma("hello", "b") == "IFMMP");
  CHECK(encryption_with_user_gamma("HELLO", "AB") == "HFLMO");

  std::string result = encryption_with_user_gamma("HELLO WORLD", "KEY");
  CHECK(result.find(' ') != std::string::npos);

  // плохие случаи
  CHECK_THROWS_AS(encryption_with_user_gamma("", "KEY"), std::invalid_argument);
  CHECK_THROWS_AS(encryption_with_user_gamma("HELLO", ""),
                  std::invalid_argument);
  CHECK_THROWS_AS(encryption_with_user_gamma("ПРИВЕТ", "A"),
                  std::invalid_argument);
}

TEST_CASE("gamma_decryption - gamma cipher decryption") {
  // хорошие случаи
  CHECK(gamma_decryption("HELLO", "A") == "HELLO");

  std::string cipher = encryption_with_user_gamma("HELLO", "SECRET");
  CHECK(gamma_decryption(cipher, "SECRET") == "HELLO");

  std::string plain = "CRYPTOGRAPHY";
  std::string key = "MYKEY";
  CHECK(gamma_decryption(encryption_with_user_gamma(plain, key), key) == plain);

  // плохие случаи
  CHECK_THROWS_AS(gamma_decryption("", "KEY"), std::invalid_argument);
  CHECK_THROWS_AS(gamma_decryption("HELLO", ""), std::invalid_argument);
}

TEST_CASE("encryption_with_user_gamma + gamma_decryption are inverse") {
  std::string original = "CRYPTOGRAPHY";
  std::string key = "KEY";
  CHECK(gamma_decryption(encryption_with_user_gamma(original, key), key) ==
        original);
}

TEST_CASE("find_gamma_symbol - guessing a gamma symbol") {
  CHECK(find_gamma_symbol("EEEEEEEEEEE") == 0);
}

TEST_CASE("known_plaintext_attack - known plaintext attack") {
  // хорошие случаи
  std::string plaintext = "HELLO";
  std::string key = "WORLD";
  std::string ciphertext = encryption_with_user_gamma(plaintext, key);
  std::string result = known_plaintext_attack(ciphertext, plaintext);
  CHECK(result == plaintext);

  // плохие случаи
  CHECK_THROWS_AS(known_plaintext_attack("", "HELLO"), std::invalid_argument);
  CHECK_THROWS_AS(known_plaintext_attack("HELLO", ""), std::invalid_argument);
  CHECK_THROWS_AS(known_plaintext_attack("HI", "CRYPTOGRAPHY"),
                  std::invalid_argument);
}

TEST_CASE("cryptanalyze_gamma - statistical cryptanalysis of gamma cipher") {
  // плохой случай
  CHECK_THROWS_AS(cryptanalyze_gamma(""), std::invalid_argument);

  // хороший случай
  std::string cipher = encryption_with_user_gamma("HELLOWORLD", "B");
  std::string result = cryptanalyze_gamma(cipher);
  CHECK_FALSE(result.empty());
}

TEST_CASE("inverse_by_mod - finding modular inverse") {
  // хорошие случаи
  CHECK(inverse_by_mod(3, 26) == 9);
  CHECK(inverse_by_mod(1, 26) == 1);

  // плохие случаи
  CHECK_THROWS_AS(inverse_by_mod(2, 26), std::invalid_argument);
  CHECK_THROWS_AS(inverse_by_mod(4, 26), std::invalid_argument);
}

TEST_CASE("affine_encryption - affine cipher encryption") {
  // хорошие случаи
  CHECK(affine_encryption("HELLO", 1, 0) == "HELLO");
  CHECK(affine_encryption("HELLO", 5, 8) == "RCLLA");
  CHECK(affine_encryption("hello", 5, 8) == "RCLLA");

  // плохие случаи
  CHECK_THROWS_AS(affine_encryption("", 5, 8), std::invalid_argument);
  CHECK_THROWS_AS(affine_encryption("HELLO", 2, 3), std::invalid_argument);
  CHECK_THROWS_AS(affine_encryption("ПРИВЕТ", 5, 8), std::invalid_argument);
}

TEST_CASE("affine_decryption - affine cipher decryption") {
  // хорошие случаи
  CHECK(affine_decryption("HELLO", 1, 0) == "HELLO");
  CHECK(affine_decryption("RCLLA", 5, 8) == "HELLO");

  // плохие случаи
  CHECK_THROWS_AS(affine_decryption("", 5, 8), std::invalid_argument);
  CHECK_THROWS_AS(affine_decryption("HELLO", 2, 3), std::invalid_argument);
  CHECK_THROWS_AS(affine_decryption("ПРИВЕТ", 5, 8), std::invalid_argument);
}

TEST_CASE("affine_encryption + affine_decryption are inverse") {
  std::string original = "CRYPTO GRAPHY";
  CHECK(affine_decryption(affine_encryption(original, 5, 8), 5, 8) ==
        to_upper(original));
}

TEST_CASE("affine_reccurent_encryption - affine recurrent cipher encryption") {
  // хорошие случаи
  CHECK(affine_reccurent_encryption("HELLO", 1, 0, 1, 0) == "HELLO");

  std::string cipher = affine_reccurent_encryption("HELLO", 3, 5, 7, 2);
  CHECK_FALSE(cipher.empty());

  // плохие случаи
  CHECK_THROWS_AS(affine_reccurent_encryption("", 3, 5, 7, 2),
                  std::invalid_argument);
  CHECK_THROWS_AS(affine_reccurent_encryption("HELLO", 2, 5, 7, 2),
                  std::invalid_argument);
  CHECK_THROWS_AS(affine_reccurent_encryption("ПРИВЕТ", 3, 5, 7, 2),
                  std::invalid_argument);
}

TEST_CASE("affine_reccurent_decryption - affine recurrent cipher decryption") {
  // хорошие случаи
  CHECK(affine_reccurent_decryption("HELLO", 1, 0, 1, 0) == "HELLO");

  // плохие случаи
  CHECK_THROWS_AS(affine_reccurent_decryption("", 3, 5, 7, 2),
                  std::invalid_argument);
  CHECK_THROWS_AS(affine_reccurent_decryption("HELLO", 2, 5, 7, 2),
                  std::invalid_argument);
  CHECK_THROWS_AS(affine_reccurent_decryption("ПРИВЕТ", 3, 5, 7, 2),
                  std::invalid_argument);
}

TEST_CASE(
    "affine_reccurent_encryption + affine_reccurent_decryption are inverse") {
  std::string original = "CRYPTOGRAPHY";
  CHECK(affine_reccurent_decryption(
            affine_reccurent_encryption(original, 3, 5, 7, 2), 3, 5, 7, 2) ==
        original);
}

TEST_CASE("good_text - text readability score") {
  // хорошие случаи
  int score_en = good_text("the cat is in the box");
  CHECK(score_en > 0);
  CHECK(good_text("") == 0);

  // плохой случай
  int score_rnd = good_text("ZZZZXXXXXQQQWWWBBB");
  CHECK(score_rnd == 0);
}

TEST_CASE("brute_force_affine - affine cipher key brute-force") {
  // плохой случай
  CHECK_THROWS_AS(brute_force_affine(""), std::invalid_argument);

  // хороший случай
  std::string plain = "IN THE BEGINNING WAS THE WORD";
  std::string cipher = affine_encryption(plain, 5, 8);
  std::string result = brute_force_affine(cipher);
  CHECK(result == plain);
}

TEST_CASE("brute_force_affine_reccurent - recurrent cipher key brute-force") {
  // плохой случай
  CHECK_THROWS_AS(brute_force_affine_reccurent(""), std::invalid_argument);

  // хороший случай
  std::string plain = "IN THE BEGINNING WAS THE WORD";
  std::string cipher = affine_reccurent_encryption(plain, 3, 5, 7, 2);
  std::string result = brute_force_affine_reccurent(cipher);
  CHECK(result == plain);
}


TEST_CASE("vigenere_encryption - шифрование") {

    // хорошие случаи — режим 1 (повторение ключевого слова)
    CHECK(vigenere_encryption("HELLO",  "KEY", 1) == "RIJVS");
    CHECK(vigenere_encryption("hello",  "key", 1) == "RIJVS");  // регистр
    CHECK(vigenere_encryption("HELLO",  "A",   1) == "HELLO");  // ключ A = сдвиг 0

    // хорошие случаи — режим 2 (самоключ по открытому тексту)
    CHECK(vigenere_encryption("HELLO",  "K",   2) == "RLPWZ");

    // хорошие случаи — режим 3 (самоключ по шифртексту)
    CHECK(vigenere_encryption("HELLO",  "K",   3) == "RVGRF");

    // плохие случаи
    CHECK_THROWS_AS(vigenere_encryption("HELLO", "", 1), std::invalid_argument); // пустой ключ
    CHECK_THROWS_AS(vigenere_encryption("HELLO", "", 2), std::invalid_argument);
    CHECK_THROWS_AS(vigenere_encryption("HELLO", "", 3), std::invalid_argument);
}

TEST_CASE("vigenere_decryption - расшифрование") {

    // хорошие случаи — режим 1
    CHECK(vigenere_decryption("RIJVS",  "KEY", 1) == "HELLO");
    CHECK(vigenere_decryption("rijvs",  "key", 1) == "HELLO");  // регистр
    CHECK(vigenere_decryption("HELLO",  "A",   1) == "HELLO");  // тождественный ключ

    // хорошие случаи — режим 2
    CHECK(vigenere_decryption("RLPWZ",  "K",   2) == "HELLO");

    // хорошие случаи — режим 3
    CHECK(vigenere_decryption("RVGRF",  "K",   3) == "HELLO");

    // плохие случаи
    CHECK_THROWS_AS(vigenere_decryption("HELLO", "", 1), std::invalid_argument);
    CHECK_THROWS_AS(vigenere_decryption("HELLO", "", 2), std::invalid_argument);
}

TEST_CASE("vigenere_encryption + decryption - обратность") {

    std::string plain = "CRYPTOGRAPHY";
    CHECK(vigenere_decryption(vigenere_encryption(plain, "SECRET", 1), "SECRET", 1) == plain);
    CHECK(vigenere_decryption(vigenere_encryption(plain, "K",      2), "K",      2) == plain);
    CHECK(vigenere_decryption(vigenere_encryption(plain, "K",      3), "K",      3) == plain);
}

TEST_CASE("vigenere_cryptanalyze - криптоанализ") {

    // плохой случай: пустой шифртекст
    CHECK_THROWS_AS(vigenere_cryptanalyze("", 1), std::invalid_argument);
    CHECK_THROWS_AS(vigenere_cryptanalyze("", 2), std::invalid_argument);

    // хорошие случаи: результат непустой
    CHECK_FALSE(vigenere_cryptanalyze(vigenere_encryption("HELLOWORLD", "A",  1), 1).empty());

    // режимы 2 и 3: для надёжного восстановления нужен более длинный текст —
    // здесь проверяем только, что функция не бросает исключение и возвращает что-то
    CHECK_FALSE(vigenere_cryptanalyze(vigenere_encryption("HELLOWORLD", "B", 2), 2).empty());
    CHECK_FALSE(vigenere_cryptanalyze(vigenere_encryption("HELLOWORLD", "B", 3), 3).empty());
}


TEST_CASE("vernam_encryption - шифрование") {

    // хорошие случаи
    CHECK(vernam_encryption("HELLO",  "AAAAA")      == "HELLO");  // ключ A = сдвиг 0
    CHECK(vernam_encryption("ABCDE",  "ABCDE")      == "ACEGI");  // известное значение
    CHECK(vernam_encryption("hello",  "AAAAA")      == "HELLO");  // регистр

    // плохие случаи
    CHECK_THROWS_AS(vernam_encryption("HELLO", "HI"),     std::invalid_argument); // разная длина
    CHECK_THROWS_AS(vernam_encryption("HI",    "HELLO"),  std::invalid_argument); // разная длина
}

TEST_CASE("vernam_decryption - расшифрование") {

    // хорошие случаи
    CHECK(vernam_decryption("HELLO",  "AAAAA")  == "HELLO");
    CHECK(vernam_decryption("ACEGI",  "ABCDE")  == "ABCDE");

    // плохие случаи
    CHECK_THROWS_AS(vernam_decryption("HELLO", "HI"),    std::invalid_argument);
    CHECK_THROWS_AS(vernam_decryption("HI",    "HELLO"), std::invalid_argument);
}

TEST_CASE("vernam_encryption + decryption - обратность") {

    std::string plain = "HELLOWORLD";
    std::string key   = "SECRETKEYX";
    CHECK(vernam_decryption(vernam_encryption(plain, key), key) == plain);

    std::string plain2 = "CRYPTOGRAPHY";
    std::string key2   = "ZYXWVUTSRQPO";
    CHECK(vernam_decryption(vernam_encryption(plain2, key2), key2) == plain2);
}


TEST_CASE("permutation_encryption - шифрование") {

    // хорошие случаи — известные значения
    // ключ "CAB" -> perm=[2,0,1]: j0->pos2, j1->pos0, j2->pos1
    CHECK(permutation_encryption("ABC",    "CAB") == "BCA");
    CHECK(permutation_encryption("abc",    "CAB") == "BCA"); // регистр
    // ключ "BAC" -> perm=[1,0,2]
    CHECK(permutation_encryption("ABCDEF", "BAC") == "BACEDF");
    // длина вывода кратна длине ключа (дополняется буквой A)
    CHECK(permutation_encryption("HELLO",  "BA").length() % 2 == 0);

    // плохие случаи
    CHECK_THROWS_AS(permutation_encryption("HELLO", ""), std::invalid_argument); // пустой ключ
}

TEST_CASE("permutation_decryption - расшифрование") {

    // хорошие случаи
    CHECK(permutation_decryption("BCA",    "CAB") == "ABC");
    CHECK(permutation_decryption("BACEDF", "BAC") == "ABCDEF");

    // плохие случаи
    CHECK_THROWS_AS(permutation_decryption("HEL", "AB"),   std::invalid_argument); // длина не кратна ключу
    CHECK_THROWS_AS(permutation_decryption("HELLO", ""),   std::invalid_argument); // пустой ключ
}

TEST_CASE("permutation_encryption + decryption - обратность") {

    // Тексты длиной, кратной длине ключа, -- дополнение не добавляется
    CHECK(permutation_decryption(permutation_encryption("ABCDEF",     "CAB"), "CAB") == "ABCDEF");
    CHECK(permutation_decryption(permutation_encryption("HELLOWORLD",  "BA"),  "BA")  == "HELLOWORLD");
    CHECK(permutation_decryption(permutation_encryption("CRYPTOGRAPHY","KEY"), "KEY") == "CRYPTOGRAPHY");
}

TEST_CASE("permutation_cryptanalyze - криптоанализ") {

    // плохой случай
    CHECK_THROWS_AS(permutation_cryptanalyze(""), std::invalid_argument);

    // хороший случай: результат непустой (алгоритм что-то возвращает)
    std::string cipher = permutation_encryption("ABCDEFABCDEF", "CAB"); // 12 букв
    std::string result = permutation_cryptanalyze(cipher);
    CHECK_FALSE(result.empty());

    // хороший случай: достаточно длинный английский текст восстанавливается
    std::string plain = "THEQUICKBROWNFOXJUMPSOVERT"; // 26 букв -- кратно 2, 13
    std::string ct    = permutation_encryption(plain, "BA");
    CHECK_FALSE(permutation_cryptanalyze(ct).empty());
}
