#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <span>

void dump(std::span<const char> buf, std::size_t offset)
{
    std::cout << std::dec;
    for (char ch : buf)
        std::cout << (ch >= ' ' ? ch : '.'), offset--;
    std::cout << std::string(offset, ' ') << std::hex
        << std::setfill('0') << std::uppercase;
    for (unsigned ch : buf)
        std::cout << std::setw(2) << ch << ' ';
    std::cout << std::dec << '\n';
}

int main()
{
    std::FILE* tmpf = std::tmpfile();
    std::fputs("Alan Turing\n", tmpf);
    std::fputs("John von Neumann\n", tmpf);
    std::fputs("Alonzo Church\n", tmpf);

    std::rewind(tmpf);
    for (char buf[8]; std::fgets(buf, sizeof buf, tmpf) != nullptr;)
        dump(buf, 10);
}