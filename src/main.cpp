#include "algorithm_dgdata/dgdata.h"
#include "algorithm_nksave/nksave.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <span>

#define HELP "Usage: %s [decrypt/encrypt] <encrypt_algorithm> [in_file] [out_file]\n" \
             "OPTIONS:\n" \
             "--dont-handle-json\tDisable automatic JSON beautifying/minifying\n"

int decryptFile(const std::string& inFile, const std::string& outFile, bool handleJson)
{
    std::ifstream inFs(inFile, std::ios::binary);
    if (!inFs.is_open() || inFs.bad())
    {
        std::cerr << "Failed to open file. Is the path valid?" << std::endl;
        return EXIT_FAILURE;
    }

    std::string decrypted;
    if (DGData::usedInFile(inFs))
    {
        std::cout << "Determined algorithm: DGData" << std::endl;
        decrypted = DGData::decrypt(inFs, handleJson);
    }
    else if (NKSave::usedInFile(inFs))
    {
        std::cout << "Determined algorithm: NKSave" << std::endl;
        decrypted = NKSave::decrypt(inFs, handleJson);
    }
    else
    {
        std::cerr << "Could not determine encryption algorithm of file" << std::endl;
        return EXIT_FAILURE;
    }

    std::ofstream outFs(outFile);
    outFs << decrypted;

    std::cout << "Decrypted data successfully and wrote to " << outFile << std::endl;
    return EXIT_SUCCESS;
}

int encryptFile(std::string algorithm, const std::string& file, const std::string& outFile, bool handleJson)
{
    std::ifstream fs(file, std::ios::binary);
    if (!fs.is_open() || fs.bad())
    {
        std::cerr << "Failed to open file. Is the path valid?" << std::endl;
        return EXIT_FAILURE;
    }

    std::ranges::transform(algorithm, algorithm.begin(), tolower);
    std::vector<char> encrypted;

    if (algorithm == "dgdata")
    {
        encrypted = DGData::encrypt(fs, handleJson);
    }
    else if (algorithm == "nksave")
    {
        encrypted = NKSave::encrypt(fs, handleJson);
    }
    else
    {
        std::cerr << "Invalid encryption algorithm given, expected DGDATA or NKSave (case insensitive)" << std::endl;
        return EXIT_FAILURE;
    }

    std::ofstream outFs(outFile);
    outFs.write(encrypted.data(), encrypted.size());

    std::cout << "Encrypted data successfully and wrote to " << outFile << std::endl;
    return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        fprintf(stderr, HELP, argv[0]);
        return EXIT_FAILURE;
    }

    bool dontHandleJson = std::ranges::any_of(std::span(argv, argc), [](char* s) {
        return strcmp(s, "--dont-handle-json") == 0;
    });

    if (strcmp(argv[1], "decrypt") == 0)
    {
        return decryptFile(argv[2], argv[3], !dontHandleJson);
    }
    else if (strcmp(argv[1], "encrypt") == 0)
    {
        if (argc >= 5)
            return encryptFile(argv[2], argv[3], argv[4], !dontHandleJson);
        else
            std::cerr << "No encryption algorithm given, expected DGDATA or NKSave (case insensitive)" << std::endl;
    }
    else
    {
        std::cerr << "Invalid option given, expected decrypt or encrypt" << std::endl;
    }

    return EXIT_FAILURE;
}
