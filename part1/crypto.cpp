#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

constexpr auto dict_filename = "./words.txt";
constexpr auto plaintext_filename = "./plaintext.txt";
constexpr auto ciphertext_filename = "./ciphertext";
constexpr auto cipher_block_size = 128 / 8;
constexpr auto key_nbytes = 128 / 8;
constexpr auto iv_nbytes = 128 / 8;

std::vector<unsigned char> read_file(const std::string &filename)
{
    std::ifstream file { filename };
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string str = buffer.str();
    return std::vector<unsigned char>(str.begin(), str.end());
}

int main()
{
    std::ifstream dict_file { dict_filename };
    auto plaintext = read_file(plaintext_filename);
    auto ciphertext = read_file(ciphertext_filename);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx { EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
    /*
     * IV is all zeros.
     */
    std::vector<unsigned char> iv (iv_nbytes);

    std::string word;
    while (std::getline(dict_file, word)) {
        std::vector<unsigned char> key { word.begin(), word.end() };
        key.resize(key_nbytes);

        if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), NULL, key.data(), iv.data())) {
            throw std::runtime_error("EVP_EncryptInit_ex() error");
        }
        std::vector<unsigned char> out(plaintext.size() + cipher_block_size - 1);
        int outlen;
        if (!EVP_EncryptUpdate(ctx.get(), out.data(), &outlen, plaintext.data(), plaintext.size())) {
            throw std::runtime_error("EVP_EncryptUpdate() error");
        }
        int tmplen;
        if (!EVP_EncryptFinal_ex(ctx.get(), out.data() + outlen, &tmplen)) {
            throw std::runtime_error("EVP_EncryptFinal_ex() error");
        }
        outlen += tmplen;
        out.resize(outlen);

        if (out == ciphertext) {
            std::cout << word << '\n';
            return 0;
        }

        EVP_CIPHER_CTX_reset(ctx.get());
    }

    return 1;
}
