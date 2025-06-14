#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "crypto.hpp"
#include <doctest/doctest.h>

TEST_CASE("AES round-trip") {
    const std::string pwd = "pass";
    fc::Buffer plain{ 'O','K' };
    auto c = fc::aes_encrypt(plain, pwd);
    CHECK(c.size() > plain.size());
    auto d = fc::aes_decrypt(c, pwd);
    CHECK_EQ(d, plain);
}

TEST_CASE("AES wrong password throws") {
    fc::Buffer plain{ 1,2,3 };
    auto c = fc::aes_encrypt(plain, "good");
    CHECK_THROWS_AS(fc::aes_decrypt(c, "bad"), std::runtime_error);
}

TEST_CASE("RSA wrap / unwrap") {
    auto [priv, pub] = fc::rsa_generate_keypair();
    fc::Buffer key{ 42, 24 };
    auto enc = fc::rsa_encrypt_key(key, pub);
    auto dec = fc::rsa_decrypt_key(enc, priv);
    CHECK_EQ(dec, key);
}