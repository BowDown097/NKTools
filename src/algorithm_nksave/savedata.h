#ifndef SAVEDATA_H
#define SAVEDATA_H
#include <fstream>
#include <vector>

class SaveData
{
public:
    // IF PASSWORD GETS CHANGED: Here's how to update it:
    // Goto `EncryptedFileWriter_WriteFileContent(...)` in cheat engine, and set a breakpoint right before the call
    // to Rfc2898DeriveBytes__ctor_1(), RDX will contain a il2cpp System.string. RDX+0x10 should be the length of
    // the string (uint64_t) and RDX+0x18 should be the password (WARNING: UTF-16 ENCODED! 2 BYTES PER CHAR!)
    // RFC2898 is paper name for PBKDF2.
    struct Constants
    {
        static constexpr int DummyHeaderBytes = 44;
        static constexpr const char* Header = "\x01\x00\x00\x00\x24\x00\x00\x00";
        static constexpr int HeaderBytes = 8;
        static constexpr int PBKDF2Iterations = 10;
        static constexpr auto PBKDF2Password = "11";
        static constexpr int PBKDF2SaltBytes = 24;
        static constexpr int TotalMetadataBytes = 76;
        static constexpr int UnknownBufferBytes = 32;
    };

    unsigned char buf[Constants::UnknownBufferBytes]; // unknown buffer, not IV/Key
    unsigned long num;
    unsigned char salt[Constants::PBKDF2SaltBytes];
    std::vector<unsigned char> strBytes;
    int strlen;
    int ver;

    explicit SaveData(std::ifstream& fs);
    static bool isSaveFile(std::ifstream& fs);
private:
    template<typename T>
    void readInto(std::ifstream& fs, T& out, size_t len) { fs.read(reinterpret_cast<char*>(&out), len); }
    template<typename T>
    void readInto(std::ifstream& fs, T& out) { readInto(fs, out, sizeof(out)); }
};

#endif // SAVEDATA_H
