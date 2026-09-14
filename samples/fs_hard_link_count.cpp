#include <filesystem>
#include <iostream>
namespace fs = std::filesystem;

int main()
{
    // On a POSIX-style filesystem, each directory has at least 2 hard links:
    // itself and the special member pathname "."
    fs::path p = fs::current_path();
    std::cout << "Number of hard links for current path is "
        << fs::hard_link_count(p) << '\n';

    // Each ".." is a hard link to the parent directory, so the total number
    // of hard links for any directory is 2 plus number of direct subdirectories
    p = fs::current_path() / ".."; // Each dot-dot is a hard link to parent
    std::cout << "Number of hard links for .. is "
        << fs::hard_link_count(p) << '\n';
}