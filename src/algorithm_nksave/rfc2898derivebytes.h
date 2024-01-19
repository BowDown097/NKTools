#ifndef RFC2898DERIVEBYTES_H
#define RFC2898DERIVEBYTES_H
#include <botan/cipher_mode.h>

struct Rfc2898DeriveBytes
{
public:
    struct Constants
    {
        static constexpr int AESBlockBytes = 16;
        static constexpr int AESKeyBytes = 16;
    };

    unsigned char iv[Constants::AESBlockBytes];
    unsigned char key[Constants::AESKeyBytes];

    Rfc2898DeriveBytes(const std::string& password, std::span<const unsigned char> salt, int iter);

    Botan::secure_vector<unsigned char> decrypt(unsigned char* data, int size)
    { return pipeOperation(data, size, Botan::Cipher_Dir::Decryption); }

    Botan::secure_vector<unsigned char> encrypt(unsigned char* data, int size)
    { return pipeOperation(data, size, Botan::Cipher_Dir::Encryption); }
private:
    Botan::secure_vector<unsigned char> pipeOperation(unsigned char* data, int size, Botan::Cipher_Dir direction);
};

#endif // RFC2898DERIVEBYTES_H
