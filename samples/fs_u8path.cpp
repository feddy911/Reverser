#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#ifdef _MSC_VER
#include <fcntl.h>
#include <io.h>
#else
#include <clocale>
#include <locale>
#endif
#include <filesystem>
#include <fstream>

int main()
{
#ifdef _MSC_VER
    _setmode(_fileno(stderr), _O_WTEXT);
#else
    std::setlocale(LC_ALL, "");
    std::locale::global(std::locale(""));
#endif

    std::filesystem::path p(u8"要らない.txt");
    std::ofstream(p) << "File contents"; // Prior to LWG2676 uses operator string_type()
                                         // on MSVC, where string_type is wstring, only
                                         // works due to non-standard extension.
                                         // Post-LWG2676 uses new fstream constructors

    // Native string representation can be used with OS-specific APIs
#ifdef _MSC_VER
    if (std::FILE* f = _wfopen(p.c_str(), L"r"))
#else
    if (std::FILE* f = std::fopen(p.c_str(), "r"))
#endif
    {
        for (int ch; (ch = fgetc(f)) != EOF; std::putchar(ch))
        {
        }
        std::fclose(f);
    }

    std::filesystem::remove(p);
}