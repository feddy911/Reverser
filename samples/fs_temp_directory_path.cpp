#include <filesystem>
#include <iostream>
namespace fs = std::filesystem;

int main()
{
    std::cout << "Temp directory is " << fs::temp_directory_path() << '\n';
}