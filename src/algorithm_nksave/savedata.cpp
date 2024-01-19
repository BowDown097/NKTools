#include "savedata.h"
#include <cstring>

SaveData::SaveData(std::ifstream& fs)
{
    readInto(fs, strlen);

    size_t sz = (2 * strlen) + 2;
    strBytes.reserve(sz);
    readInto(fs, strBytes[0], sz);

    readInto(fs, ver);
    readInto(fs, buf[0], Constants::UnknownBufferBytes);
    readInto(fs, num);
    readInto(fs, salt[0], Constants::PBKDF2SaltBytes);

    fs.seekg(0);

    if (num != 2)
        throw std::invalid_argument("File is probably not a save file");
}

bool SaveData::isSaveFile(std::ifstream& fs)
{
    char fileHead[8];
    fs.read(fileHead, sizeof(fileHead));
    fs.seekg(0);
    return strncmp(fileHead, Constants::Header, Constants::HeaderBytes) == 0;
}
