#define _CRT_SECURE_NO_WARNINGS
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>

int main()
{
    std::ofstream("dummy.nfo") << "8 bytes\n"; // create the file

    std::FILE* fp = std::fopen("dummy.nfo", "rb");
    assert(fp);

    std::fseek(fp, 0, SEEK_END); // seek to end
    const std::size_t filesize = std::ftell(fp);
    std::vector<std::uint8_t> buffer(filesize);

    std::fseek(fp, 0, SEEK_SET); // seek to start
    std::fread(buffer.data(), sizeof(std::uint8_t), buffer.size(), fp);

    std::fclose(fp);
    std::printf("I've read %zi bytes\n", filesize);
}