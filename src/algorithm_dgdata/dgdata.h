#ifndef DGDATA_H
#define DGDATA_H
#include <fstream>
#include <vector>

namespace DGData
{
    struct Constants
    {
        static constexpr const char* Header = "DGDATA";
        static constexpr int HeaderBytes = std::char_traits<char>::length(Header);
        static constexpr int HeaderWithHashBytes = HeaderBytes + 8;
    };

    std::string decrypt(std::ifstream& fs, bool handleJson);
    std::vector<char> encrypt(std::ifstream& fs, bool handleJson);
    bool usedInFile(std::ifstream& fs);
};

#endif // DGDATA_H
