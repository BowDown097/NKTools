#include "dgdata.h"
#include <cstring>
#include <format>
#include <glaze/json.hpp>

namespace DGData
{
    unsigned long NKCRC32(const std::string& data)
    {
        unsigned long crc = 0;
        static constexpr int POLY = 0xdb710641;

        for (int i = 0; i < data.size(); i++)
        {
            unsigned long c = data[i];
            c ^= crc;
            c &= 0xff;

            for (int j = 0; j < 8; j++)
            {
                if ((c & 1) != 0)
                    c ^= POLY;
                c >>= 1;
            }

            crc >>= 8;
            crc &= 0x00ffffff;
            crc ^= c;
        }

        return crc & 0x00ffffffff;
    }

    std::string decrypt(std::ifstream& fs, bool handleJson)
    {
        fs.seekg(0, fs.end);
        int sz = fs.tellg();
        fs.seekg(0, fs.beg);

        char encryptedData[sz];
        fs.read(encryptedData, sz);
        fs.close();

        for (int i = 0; i < sz; i++)
        {
            int num = i - Constants::HeaderWithHashBytes;
            if (num >= 0)
                encryptedData[i] = (int)encryptedData[i] - 21 - (num % 6);
        }

        if (strncmp(encryptedData, Constants::Header, Constants::HeaderBytes) != 0)
            throw std::runtime_error("DGData decryption failed: header not present in decrypted data");

        std::string out(encryptedData + Constants::HeaderWithHashBytes, sz - Constants::HeaderWithHashBytes);
        return handleJson && glz::validate_json(out) == glz::error_code::none ? glz::prettify(out, false, 4) : out;
    }

    std::vector<char> encrypt(std::ifstream& fs, bool handleJson)
    {
        std::string decryptedData((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
        if (handleJson && glz::validate_json(decryptedData) == glz::error_code::none)
            decryptedData = glz::minify(decryptedData);

        std::string s = std::format("DGDATA{:x}", NKCRC32(decryptedData));
        std::vector<char> encryptedData;
        encryptedData.reserve(14 + decryptedData.size());
        encryptedData.insert(encryptedData.begin(), s.begin(), s.end());

        for (int i = 0; i < decryptedData.size(); i++)
            encryptedData.push_back(decryptedData[i] + 21 + (i % 6));

        return encryptedData;
    }

    bool usedInFile(std::ifstream& fs)
    {
        char fileHead[6];
        fs.read(fileHead, sizeof(fileHead));
        fs.seekg(0);
        return strncmp(fileHead, Constants::Header, Constants::HeaderBytes) == 0;
    }
}
