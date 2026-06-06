#pragma once
#include <string>
#include <vector>

/// Английский алфавит
inline const std::string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Длина английского алфавита
inline const int ALPHABET_LENGTH = 26;

/**
 * @brief Приводит текст к верхнему регистру
 * @param text Произвольный текст
 * @return Строка только из заглавных букв
 */
std::string to_upper(std::string text);

/**
 * @brief Приводит текст к нижнему регистру
 * @param text Произвольный текст
 * @return Строка только из строчных букв
 */
std::string to_lower(std::string text);

/**
 * @brief Проверяет, что нет букв, кроме английских
 * @param text Произвольный текст
 * @throws std::invalid_argument Ошибка, если встретили букву кроме англ.
 */
void check_is_english(const std::string &text);

/**
 * @brief Генерирует случайную гамму заданной длины
 * @param length Нужная пользователю длина гаммы
 * @return Рандомно сгенерированная гамма
 */
std::string random_gamma(int length);

/**
 * @brief Составляет список индексов букв текста
 * @param text Строка букв/текст пользователя
 * @return Список индексов
 */
std::vector<int> text_to_index(std::string text);

/**
 * @brief Составляет строку из букв по их индексам
 * @param index Список индексов
 * @return Строка букв
 */
std::string index_to_text(std::vector<int> index);

/**
 * @brief Зашифровывает гаммированием со случайной гаммой
 * @param plaintext Текст пользователя (только англ буквы)
 * @return Зашифрованный текст; сгенерированная гамма выводится (иначе
 * пользователь расшифровать не сможет)
 * @throws std::invalid_argument Если текст пустой или содержит другой алфавит
 */
std::string encryption_with_random_gamma(std::string plaintext);

/**
 * @brief Зашифровывает текст гаммированием с помощью гаммы от пользователя
 * @param plaintext Текст пользователя (только англ буквы)
 * @param gamma Гамма (повторяется, если короче текста)
 * @return Зашифрованный текст
 * @throws std::invalid_argument Если текст или гамма пусты, или содержат другой
 * алфавит
 */
std::string encryption_with_user_gamma(std::string plaintext,
                                       std::string gamma);

/**
 * @brief Расшифровывает текст, зашифрованный гаммированием
 * @param ciphertext Шифртекст
 * @param gamma Гамма, использованная при шифровании
 * @return Расшифрованный текст
 * @throws std::invalid_argument Если шифртекст или гамма пусты, или содержат
 * другой алфавит
 */
std::string gamma_decryption(std::string ciphertext, std::string gamma);

/**
 * @brief Оценивает осмысленность текста по частоте гласных и наличию частых
 * слов
 * @param text Потенциальная расшифровка текста
 * @return Количество набранных баллов
 */
int good_text(std::string text);

/**
 * @brief Определяет наиболее вероятную длину гаммы
 * @param ciphertext Шифртекст
 * @return Предполагаемая длина гаммы (от 1 до 20)
 * @throws std::invalid_argument Если шифртекст пуст
 */
int gamma_length(std::string ciphertext);

/**
 * @brief Угадывает один символ гаммы, опираясь на то, что E это самая частая
 * буква
 * @param one_position_letters Строка из букв шифртекста, зашифрованных одним
 * символом гаммы
 * @return Индекс предполагаемого символа гаммы
 */
int find_gamma_symbol(std::string one_position_letters);

/**
 * @brief Атака на гаммирование с известным открытым текстом и соответствующим
 * шифртекстом
 * @param ciphertext Шифртекст
 * @param known_plaintext Соответствующий шифртексту кусок открытого текста
 * @return Расшифрованный текст
 * @throws std::invalid_argument Если один из текстов пуст, содержит другой
 * алфавит, или known_plaintext не одной длины с ciphertext
 */
std::string known_plaintext_attack(std::string ciphertext,
                                   std::string known_plaintext);

/**
 * @brief Определяет длину гаммы и расшифровывает
 * @param ciphertext Шифртекст
 * @return Предполагаемый открытый текст (длина гаммы и гамма тоже выводятся)
 * @throws std::invalid_argument Если шифртекст пустой
 */
std::string cryptanalyze_gamma(std::string ciphertext);

/**
 * @brief Ищет обратный элемент числа по заданному модулю
 * @param number Число, для которого ищется обратное
 * @param mod Модуль
 * @return Обратный элемент (i * number) % mod == 1
 * @throws std::invalid_argument Если number не взаимно просто с mod
 */
int inverse_by_mod(int number, int mod);

/**
 * @brief Зашифровывает текст аффинным шифром
 * @param plaintext Текст пользователя (только англ буквы)
 * @param alpha_key Ключ a (должен быть взаимно прост с 26)
 * @param beta_key Ключ b (сдвиг)
 * @return Шифртекст
 * @throws std::invalid_argument Если текст пуст, содержит другой алфавит или
 * alpha_key не взаимно простое с 26
 */
std::string affine_encryption(std::string plaintext, int alpha_key,
                              int beta_key);

/**
 * @brief Расшифровывает текст, зашифрованный аффинным шифром
 * @param ciphertext Шифртекст
 * @param alpha_key Ключ a, использованный при шифровании
 * @param beta_key Ключ b, использованный при шифровании
 * @return Исходный текст
 * @throws std::invalid_argument Если текст пуст, содержит другой алфавит или
 * alpha_key не взаимно простое с 26
 */
std::string affine_decryption(std::string ciphertext, int alpha_key,
                              int beta_key);

/**
 * @brief Зашифровывает текст аффинным рекуррентным шифром
 * @param plaintext Текст пользователя
 * @param alpha_key_0 Первое начальное значение ключа a
 * @param beta_key_0 Первое начальное значение ключа b
 * @param alpha_key_1 Второе начальное значение ключа a
 * @param beta_key_1 Второе начальное значение ключа b
 * @return Шифртекст
 * @throws std::invalid_argument Если текст пуст, содержит другой алфавит или
 * начальные a не взаимно простые с 26
 */
std::string affine_reccurent_encryption(std::string plaintext, int alpha_key_0,
                                        int beta_key_0, int alpha_key_1,
                                        int beta_key_1);

/**
 * @brief Расшифровывает текст, зашифрованный аффинным рекуррентным шифром
 * @param ciphertext Шифртекст
 * @param alpha_key_0 Первое начальное значение ключа a
 * @param beta_key_0 Первое начальное значение ключа b
 * @param alpha_key_1 Второе начальное значение ключа a
 * @param beta_key_1 Второе начальное значение ключа b
 * @return Исходный текст
 * @throws std::invalid_argument Если текст пуст, содержит другой алфавит, или
 * начальные a не взаимно простые с 26
 */
std::string affine_reccurent_decryption(std::string ciphertext, int alpha_key_0,
                                        int beta_key_0, int alpha_key_1,
                                        int beta_key_1);

/**
 * @brief Перебирает все допустимые ключи и возвращает наиболее осмысленную
 * расшифровку (афинный шифр)
 * @param text Шифртекст
 * @return Лучший ключ + оценка
 * @throws std::invalid_argument Если текст пуст
 */
std::string brute_force_affine(std::string text);

/**
 * @brief Перебирает ключи аффинного рекуррентного шифра и возвращает наиболее
 * осмысленную расшифровку
 * @param text Шифртекст
 * @return Лучший ключ + оценка
 * @throws std::invalid_argument Если текст пуст
 */
std::string brute_force_affine_reccurent(std::string text);

/**
 * @brief Считывает строку, введённую пользователем
 * @param users_str Приглашение, которое выводится перед вводом
 * @return Введённая строка
 */
std::string input_text(std::string users_str);

/**
 * @brief Считывает целое число, введённое пользователем
 * @param users_numb Приглашение, которое выводится перед вводом
 * @return Введённое число
 */
int input_int(std::string users_numb);

/**
 * @brief Зашифровывает текст шифром Виженера в заданном режиме.
 * @param plaintext Открытый текст.
 * @param key Ключевое слово.
 * @param mode Режим (1 - повторение лозунга, 2 - самоключ по открытому тексту,
 * 3 - самоключ по шифртексту).
 * @return Шифртекст.
 * @throws std::invalid_argument Если ключ пуст или текст содержит недопустимые
 * символы.
 */
std::string vigenere_encryption(std::string plaintext, std::string key,
                                int mode);

/**
 * @brief Расшифровывает текст, зашифрованный шифром Виженера.
 * @param ciphertext Шифртекст.
 * @param key Ключевое слово.
 * @param mode Режим (1, 2 или 3).
 * @return Открытый текст.
 * @throws std::invalid_argument Если ключ пуст или текст содержит недопустимые
 * символы.
 */
std::string vigenere_decryption(std::string ciphertext, std::string key,
                                int mode);

/**
 * @brief Выполняет криптоанализ шифра Виженера (подбор ключа без его знания).
 * @param ciphertext Шифртекст.
 * @param mode Режим, в котором производилось шифрование (1, 2 или 3).
 * @return Наиболее вероятный открытый текст.
 * @throws std::invalid_argument Если текст пуст.
 */
std::string vigenere_cryptanalyze(std::string ciphertext, int mode);

/**
 * @brief Зашифровывает текст шифром Вернама (модульное сложение).
 * @param plaintext Открытый текст.
 * @param key Ключ, равный по длине открытому тексту.
 * @return Шифртекст.
 * @throws std::invalid_argument Если длина ключа не равна длине текста.
 */
std::string vernam_encryption(std::string plaintext, std::string key);

/**
 * @brief Расшифровывает текст, зашифрованный шифром Вернама.
 * @param ciphertext Шифртекст.
 * @param key Ключ, использованный при шифровании.
 * @return Открытый текст.
 * @throws std::invalid_argument Если длина ключа не равна длине текста.
 */
std::string vernam_decryption(std::string ciphertext, std::string key);

/**
 * @brief Зашифровывает текст блочным перестановочным шифром.
 * @param plaintext Открытый текст.
 * @param key Ключевое слово, задающее порядок перестановки.
 * @return Шифртекст.
 * @throws std::invalid_argument Если ключ пуст.
 */
std::string permutation_encryption(std::string plaintext, std::string key);

/**
 * @brief Расшифровывает текст, зашифрованный блочным перестановочным шифром.
 * @param ciphertext Шифртекст.
 * @param key Ключевое слово, задающее порядок перестановки.
 * @return Открытый текст.
 * @throws std::invalid_argument Если длина текста не кратна длине ключа.
 */
std::string permutation_decryption(std::string ciphertext, std::string key);

/**
 * @brief Выполняет криптоанализ блочного перестановочного шифра перебором длин
 * блоков.
 * @param ciphertext Шифртекст.
 * @return Наиболее вероятный открытый текст.
 * @throws std::invalid_argument Если текст пуст.
 */
std::string permutation_cryptanalyze(std::string ciphertext);

/**
 * @brief Зашифровывает текст шифром простой замены (моноалфавитная подстановка)
 * @param plaintext Открытый текст (только английские буквы, регистр не важен)
 * @param key Шифралфавит — перестановка из 26 букв (ключ шифрования)
 * @return Шифртекст в верхнем регистре (только буквы)
 * @throws std::invalid_argument Если ключ не является перестановкой 26 букв или
 * текст пуст
 */
std::string simple_substitution_encrypt(std::string plaintext, std::string key);

/**
 * @brief Расшифровывает текст, зашифрованный шифром простой замены
 * @param ciphertext Шифртекст (только английские буквы, регистр не важен)
 * @param key Шифралфавит, использованный при шифровании
 * @return Открытый текст в верхнем регистре (только буквы)
 * @throws std::invalid_argument Если ключ не является перестановкой 26 букв или
 * текст пуст
 */
std::string simple_substitution_decrypt(std::string ciphertext,
                                        std::string key);

/**
 * @brief Выполняет криптоанализ шифра простой замены (дешифрование без ключа)
 * @details Использует восхождение к вершине (hill-climbing) по оценке триграмм.
 *          Найденный шифралфавит и оценка выводятся в std::cout.
 *          Точность растёт с длиной шифртекста (рекомендуется не менее 100
 * букв).
 * @param ciphertext Шифртекст для атаки
 * @param restarts Число случайных перезапусков алгоритма (по умолчанию 60)
 * @return Наиболее вероятный открытый текст
 * @throws std::invalid_argument Если шифртекст слишком короткий для анализа
 */
std::string simple_substitution_break(std::string ciphertext,
                                      int restarts = 60);

/**
 * @brief Зашифровывает текст шифром Хилла (блочный линейный шифр)
 * @details Текст делится на блоки длины n; каждый блок умножается на матрицу
 *          ключа n×n по модулю 26. Последний неполный блок дополняется буквой
 * X.
 * @param plaintext Открытый текст (английские буквы, регистр не важен)
 * @param key_values Элементы матрицы ключа в строчно-мажорном порядке (ровно
 * n*n значений)
 * @param n Порядок квадратной матрицы ключа (он же размер блока, от 1 до 8)
 * @return Шифртекст в верхнем регистре
 * @throws std::invalid_argument Если матрица не является обратимой по модулю
 * 26, размер неверный, или текст пуст
 */
std::string hill_encrypt(std::string plaintext, std::vector<int> key_values,
                         int n);

/**
 * @brief Расшифровывает текст, зашифрованный шифром Хилла
 * @param ciphertext Шифртекст (число букв должно быть кратно n)
 * @param key_values Элементы матрицы ключа в строчно-мажорном порядке (n*n
 * значений)
 * @param n Порядок матрицы ключа (он же размер блока)
 * @return Открытый текст; хвостовые символы X (дополнение) удалены
 * @throws std::invalid_argument Если ключ некорректен или длина шифртекста не
 * кратна n
 */
std::string hill_decrypt(std::string ciphertext, std::vector<int> key_values,
                         int n);

/**
 * @brief Выполняет криптоанализ шифра Хилла полным перебором 2×2 матриц
 * @details Перебирает все 157 248 обратимых матриц 2×2 по модулю 26 и выбирает
 *          ту, при расшифровании которой текст получил наивысшую триграммную
 * оценку. Найденная матрица выводится в std::cout. Работает только при размере
 * блока 2.
 * @param ciphertext Шифртекст для атаки
 * @return Наиболее вероятный открытый текст; хвостовые символы X удалены
 * @throws std::invalid_argument Если шифртекст слишком короткий
 */
std::string hill_break(std::string ciphertext);

/**
 * @brief Зашифровывает текст рекуррентным шифром Хилла
 * @details Пользователь задаёт m матриц K_1, …, K_m. Блок i шифруется матрицей
 *          K_{((i-1) mod m)+1}, т.е. матрицы циклически чередуются.
 * @param plaintext Открытый текст
 * @param keys_values Набор матриц: keys_values[j] содержит n*n элементов
 * матрицы K_{j+1} (строчно-мажорный порядок)
 * @param n Порядок каждой из матриц (он же размер блока, одинаковый для всех)
 * @return Шифртекст в верхнем регистре
 * @throws std::invalid_argument Если набор матриц пуст или матрицы некорректны
 */
std::string recurrent_hill_encrypt(std::string plaintext,
                                   std::vector<std::vector<int>> keys_values,
                                   int n);

/**
 * @brief Расшифровывает текст, зашифрованный рекуррентным шифром Хилла
 * @param ciphertext Шифртекст (число букв должно быть кратно n)
 * @param keys_values Набор матриц K_1, …, K_m (тот же, что при шифровании)
 * @param n Порядок матриц
 * @return Открытый текст; хвостовые символы X (дополнение) удалены
 * @throws std::invalid_argument Если ключ некорректен или длина шифртекста не
 * кратна n
 */
std::string recurrent_hill_decrypt(std::string ciphertext,
                                   std::vector<std::vector<int>> keys_values,
                                   int n);

/**
 * @brief Выполняет криптоанализ рекуррентного шифра Хилла
 * @details Независимо перебирает все обратимые 2×2 матрицы для каждой из
 * num_keys позиций цикла, используя потоки блоков, зашифрованных одной
 * матрицей. Найденные матрицы выводятся в std::cout.
 * @param ciphertext Шифртекст
 * @param num_keys Предполагаемое количество матриц (период цикла, >= 1)
 * @return Наиболее вероятный открытый текст; хвостовые символы X удалены
 * @throws std::invalid_argument Если шифртекст слишком короткий
 */
std::string recurrent_hill_break(std::string ciphertext, int num_keys = 1);
