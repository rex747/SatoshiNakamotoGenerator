// SatoshiNakamotoGenerator.cpp : the first Bitcoin generator based on reverse engineering of entropy
// Autor @Serge_01

#include <windows.h>             
#include <iostream>             
#include <vector>               
#include <random>               
#include <string>               
#include <stdexcept>            
#include <ctime>
#include <chrono>
#include <algorithm>
#include <wincrypt.h>           
#include <iomanip>              
#include <thread>               
#include <mutex>                
#include <atomic>
#include <fstream>
#include <openssl/sha.h>        
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>     
#include <memory>
#include <sstream>              
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <cstddef>              
#include <set>


std::mutex g_file_mutex;       // Для generated.txt
std::mutex g_file_mutex2;      // Для addresses.txt
std::mutex g_console_mutex;    // Мьютекс для консольного вывода


std::atomic<int64_t> iterationCount{ 0 };  // Атомарный счётчик
std::mutex coutMutex;                      // Для безопасного вывода

constexpr size_t SECP256K1_PUBLIC_KEY_COMPRESSED_SIZE = 33;   // Размер сжатого публичного ключа
constexpr size_t SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE = 65; // Размер несжатого публичного ключа

// Прототипы функций
std::vector<uint8_t> processorEntropy();
std::vector<uint64_t> screenEntropy();
std::vector<uint8_t> get_median_times();
std::vector<uint8_t> timeToByteVector(int hours, int minutes, int seconds, int day, int month, int year);
void writeToFile(const std::string& data);
void writeToFile2(const std::string& data);
BIGNUM* generatePrivateKey(const std::vector<unsigned char>& totalEntropy);
std::vector<unsigned char> generatePublicKey(const BIGNUM* privateKey);
std::string generateBitcoinAddress(const std::vector<unsigned char>& publicKey);
unsigned int get_seed_from_time(int hours, int minutes, int seconds, int day, int month, int year);
std::string generateBitcoinAddress(const std::vector<unsigned char>& publicKey);
void safeWriteToFiles(const std::string& key, const std::string& address);
void ThreadFunc(int64_t start, int64_t end);

// Определения функций // function definition

// Определение эмуляции процессора // definition of CPU emulation
std::vector<uint8_t> processorEntropy() {
    try {
        
        if (!IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE)) {
            std::cerr << "PF_FASTFAIL_AVAILABLE is not supported on this processor." << std::endl;
            return {};
        }
        std::vector<std::string> architectures = { "Core", "Nehalem", "K8", "K10" };
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> cores_dis(2, 4);
        std::uniform_real_distribution<> frequency_dis(1.8, 3.33);
        std::uniform_int_distribution<> l2_cache_dis(256, 1024);
        std::uniform_int_distribution<> l3_cache_dis(2, 8);
        std::uniform_int_distribution<> process_tech_dis(0, 1);
        std::vector<std::string> memory_supports = { "DDR2", "DDR3" };
        std::uniform_int_distribution<> power_consumption_dis(35, 130);

        std::string processor_info = architectures[std::uniform_int_distribution<>(0, static_cast<int>(architectures.size()) - 1)(gen)] + "|" +
            std::to_string(cores_dis(gen)) + "|" +
            std::to_string(frequency_dis(gen)) + "|" +
            std::to_string(l2_cache_dis(gen)) + "|" +
            std::to_string(l3_cache_dis(gen)) + "|" +
            std::to_string(process_tech_dis(gen) ? 45 : 65) + "|" +
            memory_supports[process_tech_dis(gen)] + "|" +
            std::to_string(power_consumption_dis(gen));

        // Преобразуем строку в вектор байтов
        std::vector<uint8_t> byte_vector(processor_info.begin(), processor_info.end());
        byte_vector.push_back('\0'); // Добавляем нулевой байт для завершения строки
        
        return byte_vector;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
    }

    return {}; // Возвращаем пустой вектор, если произошла ошибка
};

// Определение функции эмуляции экрана //definition of screen emulation function
std::vector<uint64_t> screenEntropy() {
    std::random_device rd; // Источник случайности
    std::mt19937 gen(rd()); // Генератор случайных чисел

    // Функция для получения случайной частоты обновления
    auto get_random_refresh_rate = [&gen]() {
        std::vector<uint64_t> refresh_rates = { 60, 75, 120 };
        std::uniform_int_distribution<size_t> dis(0, refresh_rates.size() - 1); // Равномерное распределение
        size_t random_index = dis(gen);
        return refresh_rates[random_index]; // Возвращаем случайную частоту обновления
        };

    // Функция для конвертации частоты в байты
    auto convert_hz_to_bytes = [](uint64_t hz, uint64_t bytes_per_frame) -> uint64_t {
        return hz * bytes_per_frame; // Общее количество байт
        };

    // Функция для получения случайного типа монитора
    auto get_random_monitor_type = [&gen]() {
        std::vector<std::string> monitor_types = { "TN", "VA", "IPS", "Plasma" };
        std::uniform_int_distribution<size_t> dis(0, monitor_types.size() - 1); // Равномерное распределение
        return monitor_types[dis(gen)]; // Возвращаем случайный тип монитора
        };

    // Функция для конвертации типа монитора в байты
    auto convert_monitor_type_to_bytes = [](const std::string& monitor_type) -> uint64_t {
        return static_cast<uint64_t>(monitor_type.size()) + 1; // Длина строки + 1 для нулевого термина
        };

    // Функция для получения случайной яркости
    auto get_random_brightness = [&gen]() {
        std::vector<uint64_t> brightness_levels = { 200, 400 };
        std::uniform_int_distribution<size_t> dis(0, brightness_levels.size() - 1); // Равномерное распределение
        return brightness_levels[dis(gen)]; // Возвращаем случайный уровень яркости
        };

    // Функция для конвертации яркости в байты
    auto convert_brightness_to_bytes = [](uint64_t brightness) -> uint64_t {
        return brightness % 256; // Гарантирует значение 0-255
        };

    // Функция для получения значений контрастности
    auto get_contrast = [&gen](const std::string& monitor_type) -> uint64_t {
        if (monitor_type == "TN") {
            std::vector<uint64_t> contrast_levels = { 1000, 1500 };
            std::uniform_int_distribution<size_t> dis(0, contrast_levels.size() - 1); // Равномерное распределение
            return contrast_levels[dis(gen)]; // Возвращаем случайное значение контрастности
        }
        else if (monitor_type == "VA") {
            std::vector<uint64_t> contrast_levels = { 1500, 2500 };
            std::uniform_int_distribution<size_t> dis(0, contrast_levels.size() - 1); // Равномерное распределение
            return contrast_levels[dis(gen)];
        }
        else if (monitor_type == "IPS") {
            std::vector<uint64_t> contrast_levels = { 2000, 3000 };
            std::uniform_int_distribution<size_t> dis(0, contrast_levels.size() - 1); // Равномерное распределение
            return contrast_levels[dis(gen)];
        }
        else if (monitor_type == "Plasma") {
            std::vector<uint64_t> contrast_levels = { 1000, 3000 };
            std::uniform_int_distribution<size_t> dis(0, contrast_levels.size() - 1); // Равномерное распределение
            return contrast_levels[dis(gen)];
        }
        return 0; // Возвращаем 0, если тип монитора не распознан
        };

    // Функция для конвертации контрастности в байты
    auto convert_contrast_to_bytes = [](uint64_t contrast) -> uint64_t {
        return contrast % 256; // Контрастность уже представлена в байтах
        };

    //Функция получения значений времени отклика экрана
    auto get_response_time = [&gen](const std::string& monitor_type) -> uint64_t {
        if (monitor_type == "TN") {
            std::vector<uint64_t> response_levels = { 2, 8 };
            std::uniform_int_distribution<size_t> dis(0, response_levels.size() - 1); // Равномерное распределение
            return response_levels[dis(gen)];
        }
        else if (monitor_type == "VA") {
            std::vector<uint64_t> response_levels = { 5, 12 };
            std::uniform_int_distribution<size_t> dis(0, response_levels.size() - 1); // Равномерное распределение
            return response_levels[dis(gen)];
        }
        else if (monitor_type == "IPS") {
            std::vector<uint64_t> response_levels = { 5, 12 };
            std::uniform_int_distribution<size_t> dis(0, response_levels.size() - 1); // Равномерное распределение
            return response_levels[dis(gen)];
        }
        else if (monitor_type == "Plasma") {
            std::vector<uint64_t> response_levels = { 5, 12 };
            std::uniform_int_distribution<size_t> dis(0, response_levels.size() - 1); // Равномерное распределение
            return response_levels[dis(gen)];
        }
        return 0; // Возвращаем 0, если тип монитора не распознан
        };

    // Функция для конвертации отклика в байты
    auto convert_response_to_bytes = [](uint64_t response) -> uint64_t {
        return response; // Уже представлена в байтах
        };

    // Функция получения угла обзора монитора
    auto get_viewing_angle = [&gen](const std::string& monitor_type) -> uint64_t {
        if (monitor_type == "TN") {
            std::vector<uint64_t> viewing_angle = { 160 };
            std::uniform_int_distribution<size_t> dis(0, viewing_angle.size() - 1); // Равномерное распределение
            return viewing_angle[dis(gen)];
        }
        else if (monitor_type == "VA" || "IPS" || "Plasma") {
            std::vector<uint64_t> viewing_angle = { 178 };
            std::uniform_int_distribution<size_t> dis(0, viewing_angle.size() - 1); // Равномерное распределение
            return viewing_angle[dis(gen)];
        }
        return 0; // Возвращаем 0, если тип монитора не распознан
        };

    // Функция для конвертации угла обзора в байты
    auto convert_viewing_angle_to_bytes = [](uint64_t viewing_angle) -> uint64_t {
        return viewing_angle; // Уже представлена в байтах
        };

    // Функция для получения случайного разрешения
    auto get_random_resolution = [&gen]() -> std::pair<uint64_t, uint64_t> {
        std::vector<std::pair<uint64_t, uint64_t>> resolutions;
        resolutions.emplace_back(800, 600);
        resolutions.emplace_back(640, 480);
        resolutions.emplace_back(1024, 768);
        resolutions.emplace_back(1280, 1024);
        resolutions.emplace_back(1440, 900);
        resolutions.emplace_back(1680, 1050);
        resolutions.emplace_back(1920, 1080);
        resolutions.emplace_back(2560, 1600);

        std::uniform_int_distribution<size_t> dis(0, resolutions.size() - 1); // Равномерное распределение
        auto& res = resolutions[dis(gen)]; // Выбираем случайное разрешение

        return res; // Возвращаем случайное разрешение
        };

    // Функция для конвертации разрешения в байты
    auto convert_resolution_to_bytes = [](uint64_t width, uint64_t height) -> std::vector<uint64_t> {
        uint64_t total = width * height * 4;
        std::vector<uint64_t> bytes;
        while (total > 0) {
            bytes.push_back(total % 256);
            total /= 256;
        }
        return bytes;
        };

    // Получение случайного разрешения и его конвертация в байты
    auto resolution = get_random_resolution();
    uint64_t width = resolution.first;    // Получаем ширину
    uint64_t height = resolution.second;   // Получаем высоту
    
    std::vector<uint64_t> result;

    // Получаем случайные значения
    uint64_t refresh_rate = get_random_refresh_rate();
    std::string monitor_type = get_random_monitor_type();
    uint64_t brightness = get_random_brightness();
    uint64_t contrast = get_contrast(monitor_type); // Получаем контрастность в зависимости от типа монитора
    uint64_t response = get_response_time(monitor_type); // Получаем отклик в зависимости от типа монитора
    uint64_t viewing = get_viewing_angle(monitor_type); // Получаем угол обзора в зависимости от типа монитора
    
    // Конвертируем в байты
    uint64_t bytes_per_refresh_rate = convert_hz_to_bytes(refresh_rate, 1); // 1 байт на кадр
    uint64_t bytes_per_monitor_type = convert_monitor_type_to_bytes(monitor_type);
    uint64_t bytes_per_brightness = convert_brightness_to_bytes(brightness); // Конвертация яркости в байты
    uint64_t bytes_per_contrast = convert_contrast_to_bytes(contrast); // Конвертация контрастности в байты
    uint64_t bytes_per_response = convert_response_to_bytes(response); // Конвертация отклика в байты
    uint64_t bytes_per_viewing = convert_viewing_angle_to_bytes(viewing); // Конвертация угла обзора в байты
    std::vector<uint64_t> resolution_bytes = convert_resolution_to_bytes(width, height); // Конвертация разрешения экрана

    // Проверяем, не превышает ли значение 255
    if (bytes_per_refresh_rate > 255 || bytes_per_monitor_type > 255 ||
        bytes_per_brightness > 255 || bytes_per_contrast > 255 ||
        bytes_per_response > 255 || bytes_per_viewing > 255) {
        throw std::overflow_error("Byte value exceeds 255");
    }

    // Добавляем значения в вектор
    result.push_back(static_cast<uint64_t>(bytes_per_refresh_rate)); // Добавляем байты частоты
    result.push_back(static_cast<uint64_t>(bytes_per_monitor_type)); // Добавляем байты типа монитора
    result.push_back(static_cast<uint64_t>(bytes_per_brightness)); // Добавляем байты яркости
    result.push_back(static_cast<uint64_t>(bytes_per_contrast)); // Добавляем байты контрастности
    result.push_back(static_cast<uint64_t>(bytes_per_response)); // Добавляем байты отклика монитора
    result.push_back(static_cast<uint64_t>(bytes_per_viewing)); // Добавляем байты угла обзора
    for (auto byte : resolution_bytes) {
        result.push_back(byte);
    } // Добавляем байты разрешения экрана

    // Добавляем каждый символ типа монитора
    for (const char& c : monitor_type) {
        result.push_back(static_cast<uint64_t>(c)); // Добавляем каждый символ типа монитора
    }
    result.push_back(0); // Добавляем нулевой терминатор для строки типа монитора
        
    return result; // Возвращаем вектор с данными
};

// Определение функции получения медианного значения времени // definition of the function for obtaining the median time value
std::vector<uint8_t> get_median_times() {
    
    std::tm start_tm = {};
    start_tm.tm_year = 0; // Год 
    start_tm.tm_mon = 0; // Январь (0-11)
    start_tm.tm_mday = 0; // число
    start_tm.tm_hour = 0; // час
    start_tm.tm_min = 0; // минут
    start_tm.tm_sec = 0; // секунд

    // Преобразуем в time_point // Convert to time_point
    auto start_time = std::chrono::system_clock::from_time_t(std::mktime(&start_tm));

    std::vector<std::chrono::system_clock::time_point> times;

    for (int i = 0; i < 5; ++i) {
        // Добавляем текущее значение start_time в список // Add the current value of start_time to the list
        times.push_back(start_time);
        // Увеличиваем значение start_time на 1 миллисекунду // Increase the value of start_time by 1 millisecond
        start_time += std::chrono::milliseconds(1);
    }

    // Сортируем времена // Sort the times
    std::sort(times.begin(), times.end());

    // Вычисляем медианное значение // Calculate the median value
    size_t median_index = times.size() / 2;
    std::chrono::system_clock::time_point median_time;

    if (times.size() % 2 == 1) {
        median_time = times[median_index];
    }
    else {
        // Если четное количество элементов, берем среднее между двумя центральными // If there is an even number of elements, take the average of the two central ones
        median_time = times[median_index - 1] + (times[median_index] - times[median_index - 1]) / 2;
    }

    // Конвертируем медианное время в миллисекунды // Convert the median time to milliseconds
    auto median_duration = median_time.time_since_epoch();
    long long median_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(median_duration).count();

    // Конвертируем в байты // Convert to bytes
    std::vector<uint8_t> result;
    result.push_back(static_cast<uint8_t>(median_milliseconds & 0xFF)); // Младший байт // Least significant byte
    result.push_back(static_cast<uint8_t>((median_milliseconds >> 8) & 0xFF)); // Второй байт // Second byte
    result.push_back(static_cast<uint8_t>((median_milliseconds >> 16) & 0xFF)); // Третий байт // Third byte
    result.push_back(static_cast<uint8_t>((median_milliseconds >> 24) & 0xFF)); // Четвертый байт // Fourth byte

    return result; // Возвращаем вектор с данными // Return the vector with the data
}

// Функция преобразования значения времени в вектор time_shtamp // Function to convert the time value into the time_stamp vector
std::vector<uint8_t> timeToByteVector(int hours, int minutes, int seconds, int day, int month, int year) {
    // Создание структуры tm и установка значений // Creating a tm structure and setting the values
    std::tm timeinfo = {};
    timeinfo.tm_year = year - 1900;  // tm_year is year since 1900
    timeinfo.tm_mon = month - 1;      // tm_mon is 0-11
    timeinfo.tm_mday = day;
    timeinfo.tm_hour = hours;
    timeinfo.tm_min = minutes;
    timeinfo.tm_sec = seconds;

    // Преобразуем время в формат UNIX timestamp // Convert the time to the UNIX timestamp format
    std::time_t timestamp = std::mktime(&timeinfo);

    // Создание вектора для хранения 16 байт // Creating a vector to store 16 bytes
    std::vector<uint8_t> byte_vector(16, 0);

    // Заполнение вектора значениями timestamp // Filling the vector with timestamp values
    std::memcpy(byte_vector.data(), &timestamp, sizeof(timestamp));

    // Дополнительные 8 байтов с произвольными значениями // Additional 8 bytes with arbitrary values
    uint64_t additional_value = static_cast<uint64_t>(timestamp) +
        static_cast<uint64_t>(seconds) +
        (static_cast<uint64_t>(minutes) * 60) +
        (static_cast<uint64_t>(hours) * 3600);
    std::memcpy(byte_vector.data() + sizeof(timestamp), &additional_value, sizeof(additional_value));

    // Проверка на размер // Checking the size
    if (byte_vector.size() != 16) {
        throw std::runtime_error("Byte vector does not have 16 bytes.");
    }
    
    return byte_vector;
};

// Эмуляция генератора псевдослучайных чисел // Emulation of a pseudo-random number generator
class XP_Random {
public:
    XP_Random() : state(0) {}

    
    void srand(unsigned int seed) {
        state = seed;
    }

    
    int rand() {
        state = (state * 214013u + 2531011u); 
        return (state >> 16) & 0x7FFF; 
    }

private:
    unsigned int state; 
};

// Функция для инициализации генератора с заданным временем (в миллисекундах) // Function to initialize the generator with a specified time (in milliseconds)
unsigned int get_seed_from_time(int hours, int minutes, int seconds, int day, int month, int year) {
    std::tm time = {};
    time.tm_hour = hours;
    time.tm_min = minutes;
    time.tm_sec = seconds;
    time.tm_mday = day;
    time.tm_mon = month - 1; 
    time.tm_year = year - 1900; // tm_year - годы с 1900

    
    std::time_t time_epoch = std::mktime(&time);
    return static_cast<unsigned int>(time_epoch * 1000); 
}


void writeToFile(const std::string& data) {
    std::lock_guard<std::mutex> lock(g_file_mutex); // Захват мьютекса
    std::ofstream f("generated.txt", std::ios::app);
    if (!f) {
        throw std::runtime_error("Failed to open file");
    }

    f << data << std::endl;
    // Файл закроется автоматически при выходе из области видимости
}


void writeToFile2(const std::string& data) {
    std::lock_guard<std::mutex> lock(g_file_mutex2); // Захват мьютекса
    std::ofstream f("addresses.txt", std::ios::app);
    if (!f) {
        throw std::runtime_error("Failed to open file");
    }

    f << data << std::endl;
}

// Функция для генерации Bitcoin-адреса // Function to generate a Bitcoin address
std::string generateBitcoinAddress(const std::vector<unsigned char>& publicKey) {
    // Хешируем публичный ключ с использованием SHA-256
    std::vector<unsigned char> sha256Hash(SHA256_DIGEST_LENGTH);
    SHA256(publicKey.data(), publicKey.size(), sha256Hash.data());

    //EVP
    std::vector<unsigned char> ripeMdHash(RIPEMD160_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_ripemd160(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP Digest Init failed");
    }

    if (EVP_DigestUpdate(mdctx, sha256Hash.data(), sha256Hash.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP Digest Update failed");
    }

    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, ripeMdHash.data(), &md_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP Digest Final failed");
    }

    EVP_MD_CTX_free(mdctx);

    //Public Key Hash
    std::vector<unsigned char> versionedHash;
    versionedHash.push_back(0x00); //Mainnet
    versionedHash.insert(versionedHash.end(), ripeMdHash.begin(), ripeMdHash.end());

    //(SHA-256)
    std::vector<unsigned char> checksum(SHA256_DIGEST_LENGTH);
    SHA256(versionedHash.data(), versionedHash.size(), checksum.data());
    SHA256(checksum.data(), checksum.size(), checksum.data()); 

    versionedHash.insert(versionedHash.end(), checksum.begin(), checksum.begin() + 4);

    //Base58
    const char* base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string result;

    BIGNUM* bn = BN_new();
    if (bn == nullptr) {
        throw std::runtime_error("Failed to create BIGNUM");
    }

    size_t size = versionedHash.size();
    if (size > INT_MAX) {
        BN_free(bn);
        throw std::runtime_error("Size exceeds maximum value for int");
    }

    if (BN_bin2bn(versionedHash.data(), static_cast<int>(size), bn) == nullptr) {
        BN_free(bn);
        throw std::runtime_error("Failed to convert binary data to BIGNUM");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        BN_free(bn);
        throw std::runtime_error("Failed to create BN_CTX");
    }

    //Base58
    while (!BN_is_zero(bn)) {
        BIGNUM* remainder = BN_new();
        if (remainder == nullptr) {
            BN_free(bn);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to create BIGNUM for remainder");
        }

        BIGNUM* divisor = BN_new();
        if (divisor == nullptr) {
            BN_free(bn);
            BN_free(remainder);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to create BIGNUM for divisor");
        }
        BN_set_word(divisor, 58);

        if (!BN_div(bn, remainder, bn, divisor, ctx)) {
            BN_free(bn);
            BN_free(remainder);
            BN_free(divisor);
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_div failed");
        }

        uint64_t index = BN_get_word(remainder);
        if (index >= 58) {
            BN_free(bn);
            BN_free(remainder);
            BN_free(divisor);
            BN_CTX_free(ctx);
            throw std::runtime_error("Invalid index in Base58 conversion");
        }

        result = base58Alphabet[index] + result;

        BN_free(remainder);
        BN_free(divisor);
    }

    
    for (unsigned char byte : versionedHash) {
        if (byte == 0x00) {
            result = '1' + result; // '1'
        }
        else {
            break;
        }
    }

    
    BN_free(bn);
    BN_CTX_free(ctx);

    return result; 
}

// Функция для генерации публичного ключа из приватного ключа // Function to generate a public key from a private key
std::vector<unsigned char> generatePublicKey(const BIGNUM* privateKey) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        throw std::runtime_error("Failed to create EC_GROUP");
    }

    EC_POINT* publicKeyPoint = EC_POINT_new(group);
    if (!publicKeyPoint) {
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to create EC_POINT");
    }

    
    if (EC_POINT_mul(group, publicKeyPoint, privateKey, nullptr, nullptr, nullptr) != 1) {
        EC_POINT_free(publicKeyPoint);
        EC_GROUP_free(group);
        throw std::runtime_error("Failed to compute public key");
    }

    
    unsigned char* publicKeyBuffer = nullptr;
    size_t publicKeyLen = EC_POINT_point2buf(
        group,
        publicKeyPoint,
        POINT_CONVERSION_UNCOMPRESSED,
        &publicKeyBuffer,
        nullptr 
    );

    if (publicKeyLen == 0) {
        EC_POINT_free(publicKeyPoint);
        EC_GROUP_free(group);
        OPENSSL_free(publicKeyBuffer);
        throw std::runtime_error("Failed to serialize public key");
    }

    
    std::vector<unsigned char> publicKey(publicKeyBuffer, publicKeyBuffer + publicKeyLen);

    
    OPENSSL_free(publicKeyBuffer);
    EC_POINT_free(publicKeyPoint);
    EC_GROUP_free(group);

    return publicKey;
}

// Функция для генерации приватного ключа из энтропии // Function to generate a private key from entropy
BIGNUM* generatePrivateKey(const std::vector<unsigned char>& totalEntropy) {
    
    if (totalEntropy.size() != 32) {
        throw std::runtime_error("Entropy must be 32 bytes");
    }

    BIGNUM* privateKey = BN_new();
    BN_bin2bn(totalEntropy.data(), 32, privateKey);

    // secp256k1
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);

    // [1, order-1]
    if (BN_cmp(privateKey, BN_value_one()) < 0 || BN_cmp(privateKey, order) >= 0) {
        BN_free(privateKey);
        BN_free(order);
        EC_GROUP_free(group);
        throw std::runtime_error("Private key is out of range");
    }

    BN_free(order);
    EC_GROUP_free(group);
    return privateKey;
}

// Функция безопасного захвата нескольких мьютексов // Function for safely acquiring multiple mutexes
void safeWriteToFiles(const std::string& key, const std::string& address) {
    // Thread-local 
    thread_local std::vector<std::pair<std::string, std::string>> buffer;
    thread_local int write_counter = 0;

    // Buffers
    buffer.emplace_back(key, address);
    write_counter++;

    
    if (write_counter >= 10) {
        std::lock(g_file_mutex, g_file_mutex2);
        std::lock_guard<std::mutex> lock1(g_file_mutex, std::adopt_lock);
        std::lock_guard<std::mutex> lock2(g_file_mutex2, std::adopt_lock);

        try {
            std::ofstream f1("generated.txt", std::ios::app);
            std::ofstream f2("addresses.txt", std::ios::app);

            for (const auto& item : buffer) {
                f1 << item.first << "\n" << item.second << "\n";
                f2 << item.second << "\n";
            }

            buffer.clear();
            write_counter = 0;

           
            f1.flush();
            f2.flush();
        }
        catch (...) {
            buffer.clear();
            write_counter = 0;
            throw;
        }
    }
}
// Функция организации потока // Function for stream organization
void ThreadFunc(int64_t thread_id, int64_t iterations) {
    try{
    // Base time
    const int hours = 0;
    const int minutes = 0;
    const int seconds = 0;
    const int day = 0;
    const int month = 0;
    const int year = 0;

    // Инициализация генератора с уникальным seed для потока // Initialization of the generator with a unique seed for the stream
    XP_Random generator;
    unsigned int base_seed = get_seed_from_time(hours, minutes, seconds, day, month, year);
    generator.srand(base_seed + static_cast<unsigned int>(thread_id));

    for (int64_t i = 0; i < iterations; ++i) {
        // 1. Генерация уникальной энтропии для каждой итерации // Generation of unique entropy for each iteration
        std::vector<uint8_t> totalEntropy;

        // Добавляем энтропию процессора (уникальную для потока) // Adding CPU entropy (unique to the stream)
        auto procEntropy = processorEntropy();
        totalEntropy.insert(totalEntropy.end(), procEntropy.begin(), procEntropy.end());

        // Добавляем энтропию экрана (уникальную для потока) // Adding screen entropy (unique to the stream)
        auto scrEntropy = screenEntropy();
        for (uint64_t value : scrEntropy) {
            totalEntropy.push_back(static_cast<uint8_t>(value & 0xFF));
            totalEntropy.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            totalEntropy.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            totalEntropy.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        }

        // Добавляем медианное время (уникальное для итерации) // Adding median time (unique to the iteration)
        auto medianTimes = get_median_times();
        totalEntropy.insert(totalEntropy.end(), medianTimes.begin(), medianTimes.end());

        // Добавляем псевдослучайные числа (уникальные для итерации) // Adding pseudorandom numbers (unique to the iteration)
        for (int j = 0; j < 10; ++j) {
            int rand_num = generator.rand();
            totalEntropy.push_back(static_cast<uint8_t>((rand_num >> 8) & 0xFF));
            totalEntropy.push_back(static_cast<uint8_t>(rand_num & 0xFF));
        }

        // 2. Нормализация энтропии до 32 байт // Normalization of entropy to 32 bytes
        if (totalEntropy.size() < 32) {
            size_t currentSize = totalEntropy.size();
            for (size_t k = currentSize; k < 32; ++k) {
                totalEntropy.push_back(totalEntropy[k % currentSize]);
            }
        }
        else if (totalEntropy.size() > 32) {
            totalEntropy.resize(32);
        }

        // 3. Генерация ключей (с автоматическим освобождением ресурсов) // Key generation (with automatic resource deallocation)
        std::unique_ptr<BIGNUM, decltype(&BN_free)>
            privateKey(generatePrivateKey(totalEntropy), BN_free);

        char* hexKey = BN_bn2hex(privateKey.get());
        std::unique_ptr<char, decltype(&free)> hexKeyPtr(hexKey, &free);

        auto publicKey = generatePublicKey(privateKey.get());
        std::string address = generateBitcoinAddress(publicKey);

        // 4. Потокобезопасная запись в файлы // Thread-safe file writing
        {
            safeWriteToFiles(hexKeyPtr.get(), address);
        }
        // Принудительный сброс буфера перед завершением потока // Forced buffer flush before thread completion
        safeWriteToFiles("", "");

        iterationCount++;
    }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> console_lock(g_console_mutex);
        std::cerr << "Error in thread " << thread_id << ": " << e.what() << std::endl;
    }

        
}


int main() {
    std::set<std::string> activationCodes = {
    "****************"                           // Для каждого пользователя - индивидуальный пароль доступа // An individual access password for each user
    };

    
    std::set<std::string> usedCodes;

    std::string userInput;
    std::cout << "Enter activation code: ";
    std::cin >> userInput;

    if (activationCodes.find(userInput) == activationCodes.end()) {
        std::cout << "Invalid activation code." << std::endl;
        return 0; 
    }

    
    if (usedCodes.find(userInput) != usedCodes.end()) {
        std::cout << "The code has already been used. The program cannot be started." << std::endl;
        return 0; 
    }

    
    usedCodes.insert(userInput);
    std::cout << "The code is accepted. The program is running." << std::endl;

    const int64_t KEYS_PER_THREAD = 10000000000;
    const int NUM_THREADS = 4;

    auto startTime = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;

    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back(ThreadFunc, i, KEYS_PER_THREAD);
    }

    // Вывод статистики в основном потоке о скорости // Output of speed statistics in the main thread
    while (std::any_of(threads.begin(), threads.end(), [](auto& t) { return t.joinable(); })) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto currentTime = std::chrono::steady_clock::now();
        double elapsedSec = std::chrono::duration<double>(currentTime - startTime).count();
        double ips = (elapsedSec > 0) ? static_cast<double>(iterationCount.load()) / elapsedSec : 0.0;

        char title[256];
        sprintf_s(title, "Iterations per second: %.2f", ips);
        SetConsoleTitleA(title);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    return 0;

}