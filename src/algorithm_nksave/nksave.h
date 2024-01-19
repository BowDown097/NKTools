#ifndef MODERNSYSTEM_H
#define MODERNSYSTEM_H
#include <fstream>
#include <vector>

namespace NKSave
{
    std::string decrypt(std::ifstream& fs, bool handleJson);
    std::vector<char> encrypt(std::ifstream& fs, bool handleJson);
    bool usedInFile(std::ifstream& fs);
};

#endif // MODERNSYSTEM_H
