#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <stdexcept>
#include <algorithm>

namespace
{
    struct EVP_CTX
    {
        EVP_CIPHER_CTX *ctx;
        EVP_CTX() : ctx(EVP_CIPHER_CTX_new())
        {
            if (!ctx)
                throw std::runtime_error("EVP_CIPHER_CTX_new() failed");
        }
        ~EVP_CTX()
        {
            if (ctx)
                EVP_CIPHER_CTX_free(ctx);
        }
        EVP_CTX(const EVP_CTX &) = delete;
        EVP_CTX &operator=(const EVP_CTX &) = delete;
    };

    inline std::runtime_error ossl_err(const char *msg)
    {
        return std::runtime_error(msg);
    }
}

// SHA-256
std::array<uint8_t, 32> fc::sha256(const Buffer &data)
{
    std::array<uint8_t, 32> out{};
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md ||
        !EVP_DigestInit_ex(md, EVP_sha256(), nullptr) ||
        !EVP_DigestUpdate(md, data.data(), data.size()) ||
        !EVP_DigestFinal_ex(md, out.data(), nullptr))
    {
        if (md)
            EVP_MD_CTX_free(md);
        throw ossl_err("SHA-256 failed");
    }
    EVP_MD_CTX_free(md);
    return out;
}

// AES-256-CBC + PBKDF2(password)
fc::Buffer fc::aes_encrypt(const Buffer &plain, const std::string &pwd)
{
    constexpr int SALT_LEN = 16, IV_LEN = 16;
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(iv, IV_LEN))
        throw ossl_err("RAND_bytes failed");

    uint8_t key[32];
    if (!PKCS5_PBKDF2_HMAC(pwd.c_str(), pwd.size(),
                           salt, SALT_LEN,
                           10000, EVP_sha256(), sizeof(key), key))
        throw ossl_err("PBKDF2 failed");

    EVP_CTX ctx;
    if (!EVP_EncryptInit_ex(ctx.ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw ossl_err("EncryptInit failed");

    Buffer cipher(plain.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, tot = 0;
    if (!EVP_EncryptUpdate(ctx.ctx, cipher.data(), &len, plain.data(), plain.size()))
        throw ossl_err("EncryptUpdate failed");
    tot = len;
    if (!EVP_EncryptFinal_ex(ctx.ctx, cipher.data() + len, &len))
        throw ossl_err("EncryptFinal failed");
    tot += len;
    cipher.resize(tot);

    Buffer out;
    out.insert(out.end(), salt, salt + SALT_LEN);
    out.insert(out.end(), iv, iv + IV_LEN);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return out;
}

fc::Buffer fc::aes_decrypt(const Buffer &data, const std::string &pwd)
{
    if (data.size() < 32)
        throw ossl_err("cipher too short");
    const uint8_t *salt = data.data();
    const uint8_t *iv = data.data() + 16;
    const uint8_t *enc = data.data() + 32;
    size_t enc_len = data.size() - 32;

    uint8_t key[32];
    if (!PKCS5_PBKDF2_HMAC(pwd.c_str(), pwd.size(),
                           salt, 16,
                           10000, EVP_sha256(), sizeof(key), key))
        throw ossl_err("PBKDF2 failed");

    EVP_CTX ctx;
    if (!EVP_DecryptInit_ex(ctx.ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw ossl_err("DecryptInit failed");

    Buffer plain(enc_len);
    int len = 0, tot = 0;
    if (!EVP_DecryptUpdate(ctx.ctx, plain.data(), &len, enc, enc_len))
        throw ossl_err("DecryptUpdate failed");
    tot = len;
    if (!EVP_DecryptFinal_ex(ctx.ctx, plain.data() + len, &len))
        throw std::runtime_error("bad password or corrupted data");
    tot += len;
    plain.resize(tot);
    return plain;
}

// RSA-2048 keypair
std::pair<std::string, std::string> fc::rsa_generate_keypair()
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY *pkey = nullptr;
    if (!pctx ||
        !EVP_PKEY_keygen_init(pctx) ||
        !EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) ||
        !EVP_PKEY_keygen(pctx, &pkey))
        throw ossl_err("RSA keygen failed");

    auto to_pem = [&](bool priv)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (priv)
            PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        else
            PEM_write_bio_PUBKEY(bio, pkey);
        BUF_MEM *m;
        BIO_get_mem_ptr(bio, &m);
        std::string s(m->data, m->length);
        BIO_free(bio);
        return s;
    };

    std::string priv = to_pem(true);
    std::string pub = to_pem(false);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return {priv, pub};
}

fc::Buffer fc::rsa_encrypt_key(const Buffer &key, const std::string &pub_pem)
{
    BIO *bio = BIO_new_mem_buf(pub_pem.data(), pub_pem.size());
    EVP_PKEY *pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pub)
        throw ossl_err("bad public PEM");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
        throw ossl_err("RSA enc init");

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, key.data(), key.size()) <= 0)
        throw ossl_err("RSA enc size");

    Buffer out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, key.data(), key.size()) <= 0)
        throw ossl_err("RSA enc");

    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    BIO_free(bio);
    return out;
}

fc::Buffer fc::rsa_decrypt_key(const Buffer &enc, const std::string &priv_pem)
{
    BIO *bio = BIO_new_mem_buf(priv_pem.data(), priv_pem.size());
    EVP_PKEY *priv = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!priv)
        throw ossl_err("bad private PEM");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)
        throw ossl_err("RSA dec init");

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, enc.data(), enc.size()) <= 0)
        throw ossl_err("RSA dec size");

    Buffer out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, enc.data(), enc.size()) <= 0)
        throw ossl_err("RSA dec");

    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    BIO_free(bio);
    return out;
}

// AES-256-CBC по raw-ключу
fc::Buffer fc::aes_encrypt_raw(const Buffer &plain, const Buffer &key)
{
    if (key.size() != 32)
        throw std::runtime_error("key must be 32 bytes");
    constexpr int IV_LEN = 16;
    uint8_t iv[IV_LEN];
    if (!RAND_bytes(iv, IV_LEN))
        throw ossl_err("RAND_bytes failed");

    EVP_CTX ctx;
    if (!EVP_EncryptInit_ex(ctx.ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv))
        throw ossl_err("raw EncryptInit failed");

    Buffer cipher(plain.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, tot = 0;
    if (!EVP_EncryptUpdate(ctx.ctx, cipher.data(), &len, plain.data(), plain.size()))
        throw ossl_err("raw EncryptUpdate failed");
    tot = len;
    if (!EVP_EncryptFinal_ex(ctx.ctx, cipher.data() + len, &len))
        throw ossl_err("raw EncryptFinal failed");
    tot += len;
    cipher.resize(tot);

    Buffer out;
    out.insert(out.end(), iv, iv + IV_LEN);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return out;
}

fc::Buffer fc::aes_decrypt_raw(const Buffer &data, const Buffer &key)
{
    if (key.size() != 32)
        throw std::runtime_error("key must be 32 bytes");
    constexpr int IV_LEN = 16;
    if (data.size() < IV_LEN)
        throw ossl_err("raw cipher too short");
    const uint8_t *iv = data.data();
    const uint8_t *enc = data.data() + IV_LEN;
    size_t enc_len = data.size() - IV_LEN;

    EVP_CTX ctx;
    if (!EVP_DecryptInit_ex(ctx.ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv))
        throw ossl_err("raw DecryptInit failed");

    Buffer plain(enc_len);
    int len = 0, tot = 0;
    if (!EVP_DecryptUpdate(ctx.ctx, plain.data(), &len, enc, enc_len))
        throw ossl_err("raw DecryptUpdate failed");
    tot = len;
    if (!EVP_DecryptFinal_ex(ctx.ctx, plain.data() + len, &len))
        throw std::runtime_error("raw bad data");
    tot += len;
    plain.resize(tot);
    return plain;
}

//------------------------------------------------------------------------------
// Генерация 256-битного AES-ключа
//------------------------------------------------------------------------------
fc::Buffer fc::generate_aes_key()
{
    Buffer key(32);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }
    return key;
}