#define _CRT_SECURE_NO_WARNINGS
#include <array>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>

void dump(std::span<const wchar_t> sp, std::size_t width = 14)
{
    for (wchar_t wc : sp)
        std::wcout << (std::iswprint(wc) ? wc : L'.');
    std::wcout << std::wstring(width > sp.size() ? width - sp.size() : 1, L' ')
        << std::hex << std::uppercase << std::setfill(L'0');
    for (wchar_t wc : sp)
        std::wcout << std::setw(sizeof wc) << static_cast<unsigned>(wc) << ' ';
    std::wcout << '\n';
}

int main()
{
    // Create temp file that contains wide characters
    std::setlocale(LC_ALL, "en_US.utf8");
    std::FILE* tmpf = std::tmpfile();

    for (const wchar_t* text : {
        L"Tétraèdre"    L"\n",
        L"Cube"         L"\n",
        L"Octaèdre"     L"\n",
        L"Icosaèdre"    L"\n",
        L"Dodécaèdre"   L"\n"
        })
        if (int rc = std::fputws(text, tmpf); rc == EOF)
        {
            std::perror("fputws()"); // POSIX requires that errno is set
            return EXIT_FAILURE;
        }

    std::rewind(tmpf);

    std::array<wchar_t, 12> buf;
    while (std::fgetws(buf.data(), buf.size(), tmpf) != nullptr)
        dump(std::span(buf.data(), buf.size()));

    return EXIT_SUCCESS;
}