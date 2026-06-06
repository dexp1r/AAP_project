#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "cipher.h"

// ─── Ключи и константы
// ────────────────────────────────────────────────────────

// Простая замена: шифралфавит и тождественный ключ
static const std::string KEY_QWERTY = "QWERTYUIOPASDFGHJKLZXCVBNM";
static const std::string KEY_IDENTITY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// K2:  матрица 2x2, det = 3*5-3*2 = 9,  НОД(9,26)  = 1  -- обратима
static const std::vector<int> K2 = {3, 3, 2, 5};
// K2b: матрица 2x2, det = 1*3-2*1 = 1,  НОД(1,26)  = 1  -- обратима
static const std::vector<int> K2b = {1, 2, 1, 3};
// K2c: матрица 2x2, det = 3*3-5*2 = 25, НОД(25,26) = 1  -- обратима
static const std::vector<int> K2c = {3, 5, 2, 3};
// K3:  матрица 3x3, det = 25,            НОД(25,26) = 1  -- обратима
// (стандартный пример)
static const std::vector<int> K3 = {6, 24, 1, 13, 16, 10, 20, 17, 15};
// K2_BAD: det = 2*8-4*6 = 18, НОД(18,26) = 2 != 1 -- НЕобратима
static const std::vector<int> K2_BAD = {2, 4, 6, 8};

// Длинный текст (175 букв, не оканчивается на X) для тестов дешифрования.
// Достаточен для надёжного восстановления триграммной моделью.
static const std::string LONG_TEXT =
    "ILIVEINABIGHOUSEONIVYSTREETITSNEARTHECOLLEGECAMPUS"
    "ISHARETHEHOUSEWITHTHREEOTHERSTUDENTSTHEIRNAMESAREBILL"
    "TONYANDPAULWEHELPEACHOTHERWITHHOMEWORKONTHEWEEKEND"
    "WEPLAYFOOTBALLTOGETHER";

// ─── Простая замена: шифрование
// ───────────────────────────────────────────────

TEST_CASE("simple_substitution_encrypt - шифрование") {
  // хорошие случаи
  CHECK(simple_substitution_encrypt("HELLO", KEY_QWERTY) == "ITSSG");
  CHECK(simple_substitution_encrypt("hello", KEY_QWERTY) ==
        "ITSSG");  // регистр
  CHECK(simple_substitution_encrypt("HELLOWORLD", KEY_QWERTY) == "ITSSGVGKSR");
  CHECK(simple_substitution_encrypt("HELLO", KEY_IDENTITY) ==
        "HELLO");  // тождественный ключ
  CHECK(simple_substitution_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", KEY_QWERTY) ==
        KEY_QWERTY);  // шифрование полного алфавита == ключ
  // небуквенные символы игнорируются; вывод -- только буквы
  CHECK(simple_substitution_encrypt("HELLO, WORLD!", KEY_QWERTY) ==
        "ITSSGVGKSR");

  // плохие случаи
  CHECK_THROWS_AS(simple_substitution_encrypt("", KEY_QWERTY),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(simple_substitution_encrypt("HELLO", "ABC"),
                  std::invalid_argument);  // ключ < 26 букв
  CHECK_THROWS_AS(simple_substitution_encrypt("HELLO", std::string(26, 'A')),
                  std::invalid_argument);  // дубликаты в ключе
}

// ─── Простая замена: расшифрование ───────────────────────────────────────────

TEST_CASE("simple_substitution_decrypt - расшифрование") {
  // хорошие случаи
  CHECK(simple_substitution_decrypt("ITSSG", KEY_QWERTY) == "HELLO");
  CHECK(simple_substitution_decrypt("itssg", KEY_QWERTY) ==
        "HELLO");  // регистр
  CHECK(simple_substitution_decrypt("ITSSGVGKSR", KEY_QWERTY) == "HELLOWORLD");
  CHECK(simple_substitution_decrypt("HELLO", KEY_IDENTITY) == "HELLO");

  // плохие случаи
  CHECK_THROWS_AS(simple_substitution_decrypt("", KEY_QWERTY),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(simple_substitution_decrypt("HELLO", "SHORT"),
                  std::invalid_argument);  // недопустимый ключ
}

// ─── Простая замена: обратность
// ───────────────────────────────────────────────

TEST_CASE("simple_substitution_encrypt + decrypt - обратность") {
  CHECK(simple_substitution_decrypt(
            simple_substitution_encrypt("HELLO", KEY_QWERTY), KEY_QWERTY) ==
        "HELLO");
  CHECK(simple_substitution_decrypt(
            simple_substitution_encrypt("CRYPTOGRAPHY", KEY_QWERTY),
            KEY_QWERTY) == "CRYPTOGRAPHY");
  CHECK(
      simple_substitution_decrypt(
          simple_substitution_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", KEY_QWERTY),
          KEY_QWERTY) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}

// ─── Простая замена: дешифрование ────────────────────────────────────────────

TEST_CASE("simple_substitution_break - дешифрование без ключа") {
  // хороший случай: 175 букв -- триграммная модель восстанавливает 100%
  CHECK(simple_substitution_break(
            simple_substitution_encrypt(LONG_TEXT, KEY_QWERTY)) == LONG_TEXT);

  // плохие случаи: шифртекст слишком короткий
  CHECK_THROWS_AS(simple_substitution_break(""), std::invalid_argument);
  CHECK_THROWS_AS(simple_substitution_break("A"), std::invalid_argument);
}

// ─── Шифр Хилла: шифрование ──────────────────────────────────────────────────

TEST_CASE("hill_encrypt - шифрование") {
  // хорошие случаи
  // "HELLO" (5 букв) -> дополнение X -> три блока HE/LL/OX
  CHECK(hill_encrypt("HELLO", K2, 2) == "HIOZHN");
  CHECK(hill_encrypt("hello", K2, 2) == "HIOZHN");  // регистр
  CHECK(hill_encrypt("HELL", K2, 2) ==
        "HIOZ");  // 4 буквы (чётное) -- без дополнения
  // длина вывода всегда кратна размеру блока
  CHECK(hill_encrypt("HELLO", K2, 2).length() == 6);  // 5 -> 6 (нечётное -> +X)
  CHECK(hill_encrypt("HELLOWORLD", K2, 2).length() == 10);  // 10 -> 10 (чётное)
  // 3x3 ключ: 5 букв -> дополнение до 6
  CHECK(hill_encrypt("HELLO", K3, 3).length() == 6);

  // плохие случаи
  CHECK_THROWS_AS(hill_encrypt("", K2, 2),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(hill_encrypt("HELLO", K2_BAD, 2),
                  std::invalid_argument);  // необратимый ключ
  CHECK_THROWS_AS(hill_encrypt("HELLO", {1, 2, 3}, 2),
                  std::invalid_argument);  // неверное число элементов
}

// ─── Шифр Хилла: расшифрование ───────────────────────────────────────────────

TEST_CASE("hill_decrypt - расшифрование") {
  // хорошие случаи
  CHECK(hill_decrypt("HIOZHN", K2, 2) ==
        "HELLO");  // хвостовой X-дополнение срезается
  CHECK(hill_decrypt("hiozhn", K2, 2) == "HELLO");  // регистр
  CHECK(hill_decrypt("HIOZ", K2, 2) ==
        "HELL");  // без дополнения -- ничего не срезается

  // плохие случаи
  CHECK_THROWS_AS(hill_decrypt("", K2, 2),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(hill_decrypt("HIZ", K2, 2),
                  std::invalid_argument);  // длина не кратна блоку
  CHECK_THROWS_AS(hill_decrypt("HIOZ", K2_BAD, 2),
                  std::invalid_argument);  // необратимый ключ
}

// ─── Шифр Хилла: обратность
// ───────────────────────────────────────────────────

TEST_CASE("hill_encrypt + hill_decrypt - обратность") {
  auto rt = [](const std::string& p, const std::vector<int>& key, int n) {
    return hill_decrypt(hill_encrypt(p, key, n), key, n);
  };
  // Тексты НЕ оканчиваются на X (иначе X-дополнение неотличимо от буквы текста)
  CHECK(rt("HELLO", K2, 2) == "HELLO");
  CHECK(rt("CRYPTOGRAPHY", K2, 2) == "CRYPTOGRAPHY");
  CHECK(rt("THEQUICKBROWNDOG", K2, 2) ==
        "THEQUICKBROWNDOG");  // не THEQUICKBROWNFOX
  CHECK(rt("HELLO", K3, 3) == "HELLO");
  CHECK(rt("CRYPTOGRAPHY", K3, 3) == "CRYPTOGRAPHY");
}

// ─── Шифр Хилла: дешифрование ────────────────────────────────────────────────

TEST_CASE("hill_break - дешифрование полным перебором (2x2)") {
  // хороший случай: 48 букв -> ключ восстанавливается точно
  const std::string p1 = "INTHEBEGINNINGWASTHEWORDANDTHEWORDINTHEBEGINNING";
  CHECK(hill_break(hill_encrypt(p1, K2, 2)) == p1);

  // хороший случай: минимально допустимая длина (4 буквы) -- не бросает
  // исключение
  CHECK_NOTHROW(hill_break(hill_encrypt("HELL", K2, 2)));

  // плохие случаи
  CHECK_THROWS_AS(hill_break(""), std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(hill_break("AB"),
                  std::invalid_argument);  // меньше 4 букв (< 2 блоков)
  CHECK_THROWS_AS(hill_break("A"), std::invalid_argument);
}

// ─── Рекуррентный шифр Хилла: шифрование ────────────────────────────────────

TEST_CASE("recurrent_hill_encrypt - шифрование") {
  // хорошие случаи
  // Одна матрица -- результат совпадает с обычным шифром Хилла
  CHECK(recurrent_hill_encrypt("HELLO", {K2}, 2) ==
        hill_encrypt("HELLO", K2, 2));
  // Две матрицы: блок 0 (HE) -> K2, блок 1 (LL) -> K2b, блок 2 (OX) -> K2 =>
  // HIHSHN
  CHECK(recurrent_hill_encrypt("HELLO", {K2, K2b}, 2) == "HIHSHN");
  CHECK(recurrent_hill_encrypt("hello", {K2, K2b}, 2) == "HIHSHN");  // регистр
  // длина вывода всегда кратна размеру блока
  CHECK(recurrent_hill_encrypt("HI", {K2}, 2).length() % 2 == 0);

  // плохие случаи
  CHECK_THROWS_AS(recurrent_hill_encrypt("HELLO", {}, 2),
                  std::invalid_argument);  // пустой набор матриц
  CHECK_THROWS_AS(recurrent_hill_encrypt("", {K2}, 2),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(recurrent_hill_encrypt("HELLO", {K2_BAD}, 2),
                  std::invalid_argument);  // необратимая матрица
  // матрицы разного размера
  CHECK_THROWS_AS(recurrent_hill_encrypt("HELLO", {K2, K3}, 2),
                  std::invalid_argument);
}

// ─── Рекуррентный шифр Хилла: расшифрование ─────────────────────────────────

TEST_CASE("recurrent_hill_decrypt - расшифрование") {
  // хорошие случаи
  CHECK(recurrent_hill_decrypt("HIHSHN", {K2, K2b}, 2) ==
        "HELLO");  // X-дополнение срезается
  CHECK(recurrent_hill_decrypt("hihshn", {K2, K2b}, 2) == "HELLO");  // регистр
  // Одна матрица -- совпадает с обычным шифром Хилла
  CHECK(recurrent_hill_decrypt("HIOZHN", {K2}, 2) == "HELLO");

  // плохие случаи
  CHECK_THROWS_AS(recurrent_hill_decrypt("", {K2}, 2),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(recurrent_hill_decrypt("HIZ", {K2}, 2),
                  std::invalid_argument);  // длина не кратна блоку
}

// ─── Рекуррентный шифр Хилла: обратность ─────────────────────────────────────

TEST_CASE("recurrent_hill_encrypt + decrypt - обратность") {
  auto rt = [](const std::string& p, const std::vector<std::vector<int>>& keys,
               int n) {
    return recurrent_hill_decrypt(recurrent_hill_encrypt(p, keys, n), keys, n);
  };
  // Тексты НЕ оканчиваются на X
  CHECK(rt("HELLO", {K2}, 2) == "HELLO");
  CHECK(rt("CRYPTOGRAPHY", {K2}, 2) == "CRYPTOGRAPHY");
  CHECK(rt("HELLO", {K2, K2b}, 2) == "HELLO");
  CHECK(rt("THEQUICKBROWNDOG", {K2, K2b}, 2) == "THEQUICKBROWNDOG");
  // три матрицы
  CHECK(rt("CRYPTOGRAPHY", {K2, K2b, K2c}, 2) == "CRYPTOGRAPHY");
}

// ─── Рекуррентный шифр Хилла: дешифрование ───────────────────────────────────

TEST_CASE("recurrent_hill_break - дешифрование полным перебором (2x2)") {
  // хороший случай: одна матрица -- работает как hill_break
  const std::string p1 = "INTHEBEGINNINGWASTHEWORDANDTHEWORDINTHEBEGINNING";
  CHECK(recurrent_hill_break(recurrent_hill_encrypt(p1, {K2}, 2), 1) == p1);

  // хороший случай: две матрицы -- 175 букв дают ~44 блока на поток (~84
  // триграммы)
  CHECK(recurrent_hill_break(recurrent_hill_encrypt(LONG_TEXT, {K2, K2b}, 2),
                             2) == LONG_TEXT);

  // плохие случаи
  CHECK_THROWS_AS(recurrent_hill_break("", 1),
                  std::invalid_argument);  // пустой текст
  CHECK_THROWS_AS(recurrent_hill_break("AB", 1),
                  std::invalid_argument);  // меньше 4 букв
  CHECK_THROWS_AS(recurrent_hill_break("ABCDEF", 0),
                  std::invalid_argument);  // num_keys < 1
}
