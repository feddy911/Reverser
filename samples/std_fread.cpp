#define _CRT_SECURE_NO_WARNINGS
#include <cstddef>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

int main()
{
    // Prepare file
    std::ofstream("test.txt") << 1 << ' ' << 2 << '\n';
    std::FILE* f = std::fopen("test.txt", "r");

    std::vector<char> buf(4); // char is trivially copyable
    const std::size_t n = std::fread(&buf[0], sizeof buf[0], buf.size(), f);

    std::cout << "Read " << n << " object" << (n > 1 ? "s" : "") << ": "
        << std::hex << std::uppercase << std::setfill('0');
    for (char n : buf)
        std::cout << "0x" << std::setw(2) << static_cast<short>(n) << ' ';
    std::cout << '\n';

    std::vector<std::string> buf2; // string is not trivially copyable
//  This would result in undefined behavior:
//  std::fread(&buf2[0], sizeof buf2[0], buf2.size(), f);
}