#include "nksave.h"
#include "rfc2898derivebytes.h"
#include "savedata.h"
#include <botan/filters.h>
#include <botan/system_rng.h>
#include <glaze/json.hpp>

#ifndef NDEBUG
#include <botan/hex.h>
#include <iostream>
#endif

namespace NKSave
{
    std::string decrypt(std::ifstream& fs, bool handleJson)
    {
        SaveData save(fs);
        Rfc2898DeriveBytes rfc2898(SaveData::Constants::PBKDF2Password, save.salt, SaveData::Constants::PBKDF2Iterations);

#ifndef NDEBUG
        std::cout << "Salt: " << Botan::hex_encode(save.salt) << std::endl;
        std::cout << "IV: " << Botan::hex_encode(rfc2898.iv) << std::endl;
        std::cout << "Key: " << Botan::hex_encode(rfc2898.key) << std::endl;
#endif

        fs.seekg(0, fs.end);
        int sz = (int)fs.tellg() - SaveData::Constants::TotalMetadataBytes;
        fs.seekg(SaveData::Constants::TotalMetadataBytes, fs.beg);

        unsigned char encryptedData[sz];
        fs.read(reinterpret_cast<char*>(encryptedData), sz);
        fs.close();

        Botan::secure_vector<unsigned char> decrypted = rfc2898.decrypt(encryptedData, sz);
        Botan::Pipe pipe(new Botan::Decompression_Filter("zlib"));
        pipe.process_msg(decrypted);

        std::string out = pipe.read_all_as_string();
        return handleJson && glz::validate_json(out) == glz::error_code::none ? glz::prettify(out, false, 4) : out;
    }

    std::vector<char> encrypt(std::ifstream& fs, bool handleJson)
    {
        std::string decryptedData((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
        if (handleJson && glz::validate_json(decryptedData) == glz::error_code::none)
            decryptedData = glz::minify(decryptedData);

        Botan::Pipe pipe(new Botan::Compression_Filter("zlib", 3));
        pipe.process_msg(decryptedData);
        Botan::secure_vector<unsigned char> compressed = pipe.read_all();

        std::vector<char> out;
        out.reserve(SaveData::Constants::DummyHeaderBytes + SaveData::Constants::HeaderBytes +
                    SaveData::Constants::PBKDF2SaltBytes + decryptedData.size());

        out.insert(out.end(), SaveData::Constants::DummyHeaderBytes, 0);
        out.push_back(2);
        out.insert(out.end(), SaveData::Constants::HeaderBytes - 1, 0);

        std::array<unsigned char, SaveData::Constants::PBKDF2SaltBytes> salt;
        Botan::system_rng().randomize(salt);
        out.insert(out.end(), salt.begin(), salt.end());

        Rfc2898DeriveBytes rfc2898(SaveData::Constants::PBKDF2Password, salt, SaveData::Constants::PBKDF2Iterations);
        Botan::secure_vector<unsigned char> encrypted = rfc2898.encrypt(compressed.data(), compressed.size());
        out.insert(out.end(), encrypted.begin(), encrypted.end());

        return out;
    }

    bool usedInFile(std::ifstream& fs)
    {
        return SaveData::isSaveFile(fs);
    }
}
