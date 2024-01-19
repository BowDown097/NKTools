#include "rfc2898derivebytes.h"
#include <botan/filters.h>
#include <botan/pwdhash.h>

Rfc2898DeriveBytes::Rfc2898DeriveBytes(const std::string& password, std::span<const unsigned char> salt, int iter)
{
    std::unique_ptr<Botan::PasswordHashFamily> family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(HMAC(SHA-1))");
    std::unique_ptr<Botan::PasswordHash> hash = family->from_params(iter);

    unsigned char derived[Constants::AESBlockBytes + Constants::AESKeyBytes];
    hash->hash(derived, password, salt);

    memcpy(iv, derived, Constants::AESBlockBytes);
    memcpy(key, derived + Constants::AESBlockBytes, Constants::AESKeyBytes);
}

Botan::secure_vector<unsigned char> Rfc2898DeriveBytes::pipeOperation(unsigned char* data, int size, Botan::Cipher_Dir direction)
{
    Botan::Pipe pipe(Botan::get_cipher("AES-128/CBC", Botan::SymmetricKey(key), Botan::InitializationVector(iv), Botan::Cipher_Dir::Decryption));
    pipe.process_msg(data, size);
    return pipe.read_all();
}
