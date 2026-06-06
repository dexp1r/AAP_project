# Cipher Application

Консольное приложение на C++17, реализующее девять классических шифров.
Каждый шифр поддерживает три операции: шифрование, расшифрование и
криптоанализ (восстановление текста без знания ключа).


## Содержание

1. [Назначение программы](#назначение-программы)
2. [Реализованные шифры](#реализованные-шифры)
3. [Требования и установка](#требования-и-установка)
4. [Сборка проекта](#сборка-проекта)
5. [Запуск приложения](#запуск-приложения)
6. [Руководство пользователя — работа с меню](#руководство-пользователя)
7. [Руководство программиста — API и примеры кода](#руководство-программиста)
8. [Запуск тестов](#запуск-тестов)
9. [Структура проекта](#структура-проекта)


## Назначение программы

Программа предназначена для учебного изучения классической криптографии.
Она позволяет:

- шифровать произвольный английский текст любым из девяти алгоритмов;
- расшифровывать шифртекст при наличии ключа;
- проводить автоматический криптоанализ — восстанавливать открытый текст
  без знания ключа методами частотного анализа и полного перебора.

Алфавит — английский, 26 букв (A–Z). Все небуквенные символы (пробелы,
знаки препинания, цифры) при шифровании игнорируются, но сохраняются на
тех же позициях в выводе для удобочитаемости.


## Реализованные шифры

| № | Шифр | Шифрование | Расшифрование | Криптоанализ |
| 1 | Простая замена | Восхождение к вершине + триграммы |
| 2 | Хилла | Полный перебор (2×2) |
| 3 | Рекуррентный Хилла | Полный перебор по позициям (2×2) |
| 4 | Аффинный | Перебор ключей |
| 5 | Аффинный рекуррентный | Перебор начальных ключей |
| 6 | Гамма (XOR-подобный) | Частотный анализ / атака с открытым текстом |
| 7 | Виженера | Метод Касиски + частотный анализ |
| 8 | Вернама | Невозможен (совершенная секретность) |
| 9 | Блочная перестановка | Перебор размеров блоков |


## Требования и установка

### Зависимости

| Инструмент | Версия | Назначение |
| Компилятор C++ | GCC ≥ 7 / Clang ≥ 5 / MSVC VS 2019+ | Сборка проекта |
| CMake | ≥ 3.15 | Система сборки |
| Интернет (опционально) | — | Загрузка Doctest для тестов |

Сторонних библиотек нет. Приложение использует только стандартную библиотеку C++17.

### Установка на Windows

1. Установите [Visual Studio 2019/2022](https://visualstudio.microsoft.com/)
   с компонентом **«Разработка классических приложений на C++».
2. Установите [CMake](https://cmake.org/download/) (или используйте встроенный
   в Visual Studio).
3. Распакуйте архив проекта.

### Установка на Linux / macOS

```bash
# Ubuntu / Debian
sudo apt install g++ cmake
```


## Сборка проекта

### Через командную строку (рекомендуется)

```bash
# 1. Перейти в папку проекта
cd cipher_app

# 2. Сгенерировать файлы сборки
cmake -S . -B build

# 3. Собрать проект
cmake --build build

# 4. Запустить приложение
./build/cipher_app          # Linux / macOS
build\Debug\cipher_app.exe  # Windows
```

### Через Visual Studio (папка как CMake-проект)

1. File → Open → Folder... → выбрать папку `cipher_app`
2. Visual Studio обнаружит `CMakeLists.txt` автоматически
3. Подождать завершения конфигурации CMake (индикатор внизу)
4. Build → Build All (или `Ctrl+Shift+B`)
5. Выбрать `cipher_app` как запускаемый элемент и нажать Run

### Генерация HTML-документации (Doxygen)

```bash
# Установить Doxygen (если не установлен)
sudo apt install doxygen      # Linux
brew install doxygen          # macOS

# Сгенерировать документацию
cd cipher_app
doxygen Doxyfile

# Открыть в браузере
xdg-open docs/html/index.html   # Linux
open docs/html/index.html        # macOS
# Windows: двойной клик на docs\html\index.html
```


## Запуск приложения

После сборки запустите `cipher_app` из терминала или двойным щелчком.
При запуске откроется текстовое меню:

```
Menu
1. Simple Substitution Cipher
2. Hill Cipher
3. Recurrent Hill Cipher
4. Affine Cipher
5. Affine Recurrent Cipher
6. Gamma Cipher
7. Vigenere Cipher
8. Vernam Cipher
9. Block Permutation Cipher
0. Exit
Choice:
```

Введите номер шифра, затем номер операции (1 — шифрование, 2 — расшифрование,
3 — криптоанализ). При вводе неверного символа программа попросит ввести снова.


## Руководство пользователя

### Общие правила

Текст вводится в любом регистре; буквы приводятся к верхнему автоматически.
Пробелы, запятые, точки и другие небуквенные символы **сохраняются** в выводе
  на тех же позициях (при шифровании Хилла — в конце добавляется буква `X`,
  которая автоматически удаляется при расшифровании).
При неверном ключе программа выводит сообщение `Error :(` и возвращает
  в подменю шифра.


### 1. Простая замена

Ключ — перестановка алфавита из 26 букв: позиция `i` задаёт, в какую
букву превращается `i`-я буква стандартного алфавита.

Пример — шифрование:
```
-Simple Substitution Cipher-
[1] Encrypt
Choice: 1
Plaintext: Hello, World!
Cipher alphabet (26 letters): QWERTYUIOPASDFGHJKLZXCVBNM
Result: ITSSG, VGKSR!
```

Пример — расшифрование:
```
Choice: 2
Ciphertext: ITSSG, VGKSR!
Cipher alphabet (26 letters): QWERTYUIOPASDFGHJKLZXCVBNM
Result: HELLO, WORLD!
```

Пример — криптоанализ (без ключа):
```
Choice: 3
Ciphertext: O SOCT OF Q WOU IGXLT GF OCN LZKTTZ...
  recovered cipher alphabet (A->): QWERTYUIOPASDFGHJKLZXCVBNM
  Fitness score: -574.18
Result: I LIVE IN A BIG HOUSE ON IVY STREET...
```
> Рекомендуется шифртекст длиной не менее 100 букв для надёжного восстановления.


### 2. Шифр Хилла

Ключ — квадратная матрица n×n над Z₂₆, обратимая по модулю 26
(det матрицы должен быть взаимно прост с 26).

Пример — шифрование матрицей 2×2:
```
-Hill Cipher-
Choice: 1
Matrix order n (block size): 2
Enter 4 matrix elements (row by row): 3 3 2 5
Plaintext: Hello, World!
Ciphertext: HIOZJZ, KHHWZL!
```

Пример — расшифрование:
```
Choice: 2
Matrix order n (block size): 2
Enter 4 matrix elements (row by row): 3 3 2 5
Ciphertext: HIOZJZ, KHHWZL!
Plaintext: HELLO, WORLD!
```

Пример — криптоанализ (только для матриц 2×2):
```
Choice: 3
Note: brute-force is supported only for a 2x2 key.
Ciphertext: FTJRKWNABQUBYYAEDPYT...
  recovered key matrix [3 3; 2 5]
  Fitness score: -136.04
Result: ILIVEINABIGHOUSEON...
```

> Допустимые размеры блока для шифрования/расшифрования: 1–8.
> Криптоанализ поддерживается только для блока 2 (перебор 157 248 матриц).


### 3. Рекуррентный шифр Хилла

Пользователь задаёт m матриц; блок `i` шифруется матрицей
`K_((i-1) mod m + 1)` — матрицы циклически чередуются.

Пример — шифрование двумя матрицами 2×2:
```
-Recurrent Hill Cipher-
Choice: 1
Number of key matrices: 2
Matrix order n (same for all matrices): 2
K1 - Enter 4 elements (row by row): 3 3 2 5
K2 - Enter 4 elements (row by row): 1 2 1 3
Plaintext: Hello!
Ciphertext: HIHSHN!
```

Пример — криптоанализ:
```
Choice: 3
Ciphertext: HIHSHN...
Number of key matrices to recover (period): 2
  recovered 2 key matrix(ces): K1=[3 3; 2 5] K2=[1 2; 1 3]
  Fitness score: -697.62
Result: HELLO...
```

> Для надёжного восстановления нужно ≥ 40 букв шифртекста на каждую матрицу.


### 4. Аффинный шифр

Ключ — пара чисел `(a, b)`, где `a` взаимно просто с 26.
Допустимые значения `a`: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.

```
Choice: 1
Enter your text: Hello
Enter key a: 5
Enter key b: 8
Result: RCLLA
```


### 5. Аффинный рекуррентный шифр

Ключ — четыре числа `(a0, b0, a1, b1)`. Последующие ключи генерируются
рекуррентно: `a_i = (a_{i-2} · a_{i-1}) mod 26`.

```
Choice: 1
Enter your text: HELLO
Enter key a0: 3
Enter key b0: 5
Enter key a1: 7
Enter key b1: 2
Result: HMRHY
```


### 6. Гамма-шифр

Режимы шифрования:
`[1]` — случайная гамма (генерируется автоматически, выводится на экран)
`[2]` — гамма, введённая пользователем (повторяется циклически)

```
Choice: 2
Enter your text: HELLO
Gamma: KEY
Result: RIJVS
```

Криптоанализ с известным фрагментом открытого текста:
```
Choice: 5
Enter your ciphertext: RIJVS
Known plaintext fragment: HELL
Found gamma segment: KCKE
Result: HELLO
```


### 7. Шифр Виженера

Поддерживает три режима:
- `1` — повторение ключевого слова
- `2` — самоключ по открытому тексту
- `3` — самоключ по шифртексту

```
Choice: 1
Select mode: 1
Enter your text: HELLO
Enter keyword: KEY
Result: RIJVS
```


### 8. Шифр Вернама

Ключ должен быть той же длины, что и текст.

```
Choice: 1
Enter your text: HELLO
Enter key (same length as text): XMCKL
Result: EQNBT
```


### 9. Блочная перестановка

Ключ — текстовое слово; порядок перестановки определяется
алфавитным порядком букв ключа.

```
Choice: 1
Enter your text: HELLOWORLD
Enter text key (e.g. 'CAB'): KEY
Result: ELHLROOWDL
```


## Руководство программиста

Проект состоит из двух библиотек (`cipher_lib` и `classical_cipher_lib`),
которые предоставляют публичное API через заголовочные файлы `cipher.h`
и `ciphers.hpp` / `crypto_utils.hpp`.

### Подключение к своему проекту

Скопируйте нужные `.cpp` и `.h`/`.hpp` файлы и добавьте их в сборку:

```cmake
# В своём CMakeLists.txt
add_executable(my_app main.cpp
    crypto_utils.cpp language_model.cpp
    simple_substitution.cpp hill.cpp recurrent_hill.cpp
    cipher_classical.cpp
    cipher_utils.cpp cipher_affine.cpp ...
)
target_include_directories(my_app PRIVATE /path/to/cipher_app)
```


### Простая замена — API

```cpp
#include "cipher.h"

// Шифрование
std::string ct = simple_substitution_encrypt("Hello World",
                                              "QWERTYUIOPASDFGHJKLZXCVBNM");
// ct == "ITSSGVGKSR"

// Расшифрование
std::string pt = simple_substitution_decrypt(ct,
                                              "QWERTYUIOPASDFGHJKLZXCVBNM");
// pt == "HELLOWORLD"

// Криптоанализ (без ключа)
std::string recovered = simple_substitution_break(ct, /*restarts=*/60);
// recovered — наиболее вероятный открытый текст
```

Исключения:
```cpp
try {
    simple_substitution_encrypt("HELLO", "ABC");  // ключ < 26 букв
} catch (const std::invalid_argument& e) {
    std::cerr << e.what();  // "The substitution key must contain exactly 26 letters"
}
```


### Шифр Хилла — API

```cpp
#include "cipher.h"

// Шифрование матрицей 2×2
// key_values — элементы матрицы в строчно-мажорном порядке
std::vector<int> key = {3, 3, 2, 5};  // матрица [[3,3],[2,5]], det=9
std::string ct = hill_encrypt("HELLO", key, /*n=*/2);
// ct == "HIOZHN"

// Расшифрование (хвостовой символ X убирается автоматически)
std::string pt = hill_decrypt(ct, key, 2);
// pt == "HELLO"

// Криптоанализ (только для матриц 2×2)
std::string recovered = hill_break(ct);
```

Шифрование матрицей 3×3:
```cpp
std::vector<int> key3x3 = {6, 24, 1, 13, 16, 10, 20, 17, 15};
std::string ct = hill_encrypt("ATTACKATDAWN", key3x3, 3);
std::string pt = hill_decrypt(ct, key3x3, 3);
// pt == "ATTACKATDAWN"
```


### Рекуррентный шифр Хилла — API

```cpp
#include "cipher.h"

// Две матрицы 2×2
std::vector<std::vector<int>> keys = {
    {3, 3, 2, 5},   // K1
    {1, 2, 1, 3}    // K2
};

std::string ct = recurrent_hill_encrypt("HELLO", keys, /*n=*/2);
// ct == "HIHSHN"

std::string pt = recurrent_hill_decrypt(ct, keys, 2);
// pt == "HELLO"

// Криптоанализ: указать ожидаемое количество матриц
std::string recovered = recurrent_hill_break(ct, /*num_keys=*/2);
```


### Прямое использование классов (ciphers.hpp)

Для более гибкой работы можно использовать классы напрямую:

```cpp
#include "ciphers.hpp"
#include "crypto_utils.hpp"

// Шифр Хилла через класс
crypto::Matrix key = crypto::Matrix::FromValues(2, 2, {3, 3, 2, 5});
crypto::HillCipher cipher(key);

std::string ct = cipher.Encrypt("HELLO WORLD");
std::string pt = cipher.Decrypt(ct);

// Криптоанализ через класс
crypto::AttackResult result = crypto::HillCipher::Break(ct, /*block_size=*/2);
std::cout << result.key_description << "\n";  // "recovered key matrix [3 3; 2 5]"
std::cout << result.plaintext << "\n";
std::cout << result.score << "\n";            // триграммная оценка
```

```cpp
// Простая замена через класс
crypto::SimpleSubstitutionCipher sub("QWERTYUIOPASDFGHJKLZXCVBNM");
std::string ct = sub.Encrypt("HELLO");
std::string pt = sub.Decrypt(ct);

// Получить восстановленный ключ из результата Break
crypto::AttackResult res = crypto::SimpleSubstitutionCipher::Break(ct, 60);
std::cout << res.key_description;  // "recovered cipher alphabet (A->): ..."
```

```cpp
// Рекуррентный Хилл через класс
std::vector<crypto::Matrix> keys = {
    crypto::Matrix::FromValues(2, 2, {3, 3, 2, 5}),
    crypto::Matrix::FromValues(2, 2, {1, 2, 1, 3})
};
crypto::RecurrentHillCipher rh(keys);
std::string ct = rh.Encrypt("HELLO");
std::string pt = rh.Decrypt(ct);
```


### Языковая модель — триграммы

Для оценки «похожести» текста на английский используется класс `LanguageModel`:

```cpp
#include "language_model.hpp"

crypto::LanguageModel model;

// Оценка текста по триграммам (чем выше, тем больше похоже на английский)
double score = model.Score("HELLOWORLD");

// Отдельная триграмма: log10-вероятность трёх букв подряд
double p = model.Trigram(7, 4, 11);  // H=7, E=4, L=11 → вероятность "HEL"
```


### Работа с матрицами (crypto_utils.hpp)

```cpp
#include "crypto_utils.hpp"

// Создание матрицы
crypto::Matrix m = crypto::Matrix::FromValues(2, 2, {3, 3, 2, 5});
// или: crypto::Matrix::Identity(3)  // единичная 3×3

// Элементы
int val = m.at(0, 1);  // строка 0, столбец 1 → 3
m.set(0, 0, 7);        // установить элемент (0,0) = 7

// Операции
crypto::Matrix product  = m.Multiply(m);     // m * m mod 26
crypto::Matrix inv      = m.InverseMod();    // обратная матрица mod 26
crypto::Matrix powered  = m.Power(3);        // m^3 mod 26
int det = m.DeterminantMod();                // определитель mod 26

std::cout << m.ToString();  // "[3 3; 2 5]"
```


### Обработка ошибок

Все функции генерируют `std::invalid_argument` при некорректных входных данных:

```cpp
// Через wrapper-функции (cipher.h)
try {
    hill_encrypt("HELLO", {2, 4, 6, 8}, 2);  // необратимый ключ
} catch (const std::invalid_argument& e) {
    std::cerr << "Ошибка: " << e.what() << "\n";
}

// Через классы (ciphers.hpp) — исключения типа crypto::CipherError
try {
    crypto::Matrix bad = crypto::Matrix::FromValues(2, 2, {2, 4, 6, 8});
    crypto::HillCipher cipher(bad);
} catch (const crypto::InvalidKeyError& e) {
    std::cerr << "Неверный ключ: " << e.what() << "\n";
} catch (const crypto::CipherError& e) {
    std::cerr << "Ошибка шифра: " << e.what() << "\n";
}
```

**Иерархия исключений:**
```
std::runtime_error
└── crypto::CipherError
    ├── crypto::InvalidKeyError          — некорректный ключ
    ├── crypto::InvalidInputError        — некорректный входной текст
    ├── crypto::MatrixError              — ошибка матричных операций
    ├── crypto::NonInvertibleMatrixError — матрица необратима mod 26
    └── crypto::CryptanalysisError       — криптоанализ невозможен
```


## Запуск тестов

Тесты написаны с использованием фреймворка Doctest (загружается
автоматически через CMake при наличии интернета).

```bash
# Сборка с тестами
cmake -S . -B build
cmake --build build

# Запуск всех тестов через ctest
cd build
ctest --output-on-failure

# Или напрямую
./test_cipher     # тесты старых шифров (аффинный, гамма, Виженер, ...)
./test_classical  # тесты новых шифров (простая замена, Хилл, рекуррентный Хилл)
```

**Ожидаемый результат:**
```
[doctest] test cases: 12 | 12 passed | 0 failed | 0 skipped
[doctest] assertions: 69 | 69 passed | 0 failed |
[doctest] Status: SUCCESS!
```


## Структура проекта

```
cipher_app/
│
├── CMakeLists.txt              # Сборка проекта
├── .clang-format               # Стиль форматирования (Google C++ Style)
├── Doxyfile                    # Конфигурация генератора документации
├── README.md                   # Это руководство
│
├── cipher.h                    # Главный публичный заголовок: объявления
│                               # всех 9 шифров в виде свободных функций
│                               # + полная Doxygen-документация
│
├── ciphers.hpp                 # Объявления классов SimpleSubstitutionCipher,
│                               # HillCipher, RecurrentHillCipher
├── crypto_utils.hpp            # Класс Matrix, исключения, вспомогательные
│                               # функции (Mod, Gcd, ModInverse, Normalize, ...)
├── language_model.hpp          # Класс LanguageModel (триграммная оценка)
│
├── cipher_utils.cpp            # Вспомогательные функции ввода/вывода
├── cipher_affine.cpp           # Аффинный шифр
├── cipher_affine_recurrent.cpp # Аффинный рекуррентный шифр
├── cipher_gamma.cpp            # Гамма-шифр
├── vigenere.cpp                # Шифр Виженера
├── vernam.cpp                  # Шифр Вернама
├── permutation.cpp             # Блочная перестановка
│
├── crypto_utils.cpp            # Реализация Matrix, Mod, ModInverse, ...
├── language_model.cpp          # Встроенная таблица триграмм (17 576 значений)
├── simple_substitution.cpp     # Шифр простой замены
├── hill.cpp                    # Шифр Хилла
├── recurrent_hill.cpp          # Рекуррентный шифр Хилла
├── cipher_classical.cpp        # Обёртки простой замены/Хилла в стиле cipher.h
│
├── main.cpp                    # Консольный интерфейс (меню)
│
├── test_cipher.cpp             # Тесты аффинного, гамма, Виженера, ...
└── test_classical.cpp          # Тесты простой замены, Хилла, рекуррентного Хилла
```
