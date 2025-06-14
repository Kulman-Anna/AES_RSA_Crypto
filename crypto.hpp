#pragma once
/**
 * @file crypto.hpp
 * @brief Симметричное (пароль + raw-ключ) и асимметричное шифрование на OpenSSL.
 */

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fc
{
    using Buffer = std::vector<uint8_t>;

    /** SHA-256 от произвольного буфера. */
    [[nodiscard]] std::array<uint8_t, 32> sha256(const Buffer &data);

    /** AES-256-CBC + PBKDF2(password) → salt|iv|cipher. */
    [[nodiscard]] Buffer aes_encrypt(const Buffer &plain, const std::string &pwd);

    /** Расшифровка AES-256-CBC + проверка целостности. */
    [[nodiscard]] Buffer aes_decrypt(const Buffer &cipher, const std::string &pwd);

    /** Генерация {priv, pub} RSA-2048 в PEM. */
    [[nodiscard]] std::pair<std::string, std::string> rsa_generate_keypair();

    /** Обёртка raw-ключа публичным RSA. */
    [[nodiscard]] Buffer rsa_encrypt_key(const Buffer &key, const std::string &pub_pem);

    /** Снятие обёртки приватным RSA → raw-ключ. */
    [[nodiscard]] Buffer rsa_decrypt_key(const Buffer &enc_key, const std::string &priv_pem);

    /**
     * @brief AES-256-CBC по **сырым** 32-байтному ключу.
     * @param plain данные
     * @param key   ровно 32 байта
     * @return      iv(16) || ciphertext
     */
    [[nodiscard]] Buffer aes_encrypt_raw(const Buffer &plain, const Buffer &key);

    /**
     * @brief Расшифровка AES-256-CBC по сырому ключу.
     * @param data iv(16) || ciphertext
     * @param key  ровно 32 байта
     * @return     исходный plaintext
     */
    [[nodiscard]] Buffer aes_decrypt_raw(const Buffer &data, const Buffer &key);

    /**
     * @brief Сгенерировать крипто-стойкий 256-битный AES-ключ.
     * @return вектор из 32 случайных байт.
     * @throws std::runtime_error при ошибке генерации.
     */
    [[nodiscard]] Buffer generate_aes_key();
} // namespace fc