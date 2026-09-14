#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>

int main()
{
    auto p = std::filesystem::temp_directory_path() / "example.bin";
    std::ofstream{ p }.put('a');
    std::cout.imbue(std::locale{ "en_US.UTF8" });
    std::cout << "File size:  " << std::filesystem::file_size(p) << '\n'
        << "Free space: " << std::filesystem::space(p).free << '\n';
    std::filesystem::resize_file(p, 64 * 1024); // resize to 64 KB
    std::cout << "File size:  " << std::filesystem::file_size(p) << '\n'
        << "Free space: " << std::filesystem::space(p).free << '\n';
    std::filesystem::remove(p);
}