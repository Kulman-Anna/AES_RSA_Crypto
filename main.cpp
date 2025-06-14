#include "crypto.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

/** Прочитать весь файл в Buffer */
static fc::Buffer read_bin(const std::string &p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open: " + p);
    return fc::Buffer(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>());
}

/** Записать Buffer в файл */
static void write_bin(const std::string &p, const fc::Buffer &b)
{
    std::ofstream f(p, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot create: " + p);
    f.write(reinterpret_cast<const char *>(b.data()), b.size());
}

static void usage(const char *prog)
{
    std::cerr << "Usage:\n"
              << "  " << prog << " enc               <in> <out> <password>\n"
              << "  " << prog << " dec               <in> <out> <password>\n"
              << "  " << prog << " genkeys           <prefix>\n"
              << "  " << prog << " wrapkey           <key.bin> <pub.pem> <out.bin>\n"
              << "  " << prog << " unwrapkey         <in.bin>  <priv.pem> <out.bin>\n"
              << "  " << prog << " encrypt_with_key  <key.bin> <in> <out>\n"
              << "  " << prog << " decrypt_with_key  <key.bin> <in> <out>\n"
              << "  " << prog << " genrawkey         <out_key.bin>\n";
}

int main(int argc, char *argv[])
{
    try
    {
        if (argc < 2)
        {
            usage(argv[0]);
            return 1;
        }
        std::string cmd = argv[1];

        if (cmd == "enc")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto in = read_bin(argv[2]);
            auto out = fc::aes_encrypt(in, argv[4]);
            write_bin(argv[3], out);
            std::cout << "Encrypted OK\n";
            return 0;
        }

        if (cmd == "dec")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto in = read_bin(argv[2]);
            auto out = fc::aes_decrypt(in, argv[4]);
            write_bin(argv[3], out);
            std::cout << "Decrypted OK\n";
            return 0;
        }

        if (cmd == "genkeys")
        {
            if (argc != 3)
            {
                usage(argv[0]);
                return 1;
            }
            auto [priv, pub] = fc::rsa_generate_keypair();
            write_bin(std::string(argv[2]) + "_priv.pem", fc::Buffer(priv.begin(), priv.end()));
            write_bin(std::string(argv[2]) + "_pub.pem", fc::Buffer(pub.begin(), pub.end()));
            std::cout << "Keys generated\n";
            return 0;
        }

        if (cmd == "wrapkey")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto key = read_bin(argv[2]);
            auto pubpem = std::string((char *)read_bin(argv[3]).data());
            auto wrapped = fc::rsa_encrypt_key(key, pubpem);
            write_bin(argv[4], wrapped);
            std::cout << "Key wrapped\n";
            return 0;
        }

        if (cmd == "unwrapkey")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto wrapped = read_bin(argv[2]);
            auto privpem = std::string((char *)read_bin(argv[3]).data());
            auto key = fc::rsa_decrypt_key(wrapped, privpem);
            write_bin(argv[4], key);
            std::cout << "Key unwrapped\n";
            return 0;
        }

        if (cmd == "encrypt_with_key")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto key = read_bin(argv[2]);
            auto in = read_bin(argv[3]);
            auto out = fc::aes_encrypt_raw(in, key);
            write_bin(argv[4], out);
            std::cout << "Encrypted with key OK\n";
            return 0;
        }

        if (cmd == "decrypt_with_key")
        {
            if (argc != 5)
            {
                usage(argv[0]);
                return 1;
            }
            auto key = read_bin(argv[2]);
            auto in = read_bin(argv[3]);
            auto out = fc::aes_decrypt_raw(in, key);
            write_bin(argv[4], out);
            std::cout << "Decrypted with key OK\n";
            return 0;
        }

        if (cmd == "genrawkey")
        {
            if (argc != 3)
            {
                usage(argv[0]);
                return 1;
            }
            auto key = fc::generate_aes_key();
            write_bin(argv[2], key);
            std::cout << "Raw AES key generated OK\n";
            return 0;
        }

        usage(argv[0]);
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}