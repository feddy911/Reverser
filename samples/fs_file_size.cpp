#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;

struct HumanReadable
{
    std::uintmax_t size{};

private:
    friend std::ostream& operator<<(std::ostream& os, HumanReadable hr)
    {
        int o{};
        double mantissa = hr.size;
        for (; mantissa >= 1024.; mantissa /= 1024., ++o);
        os << std::ceil(mantissa * 10.) / 10. << "BKMGTPE"[o];
        return o ? os << "B (" << hr.size << ')' : os;
    }
};

int main(int, char const* argv[])
{
    fs::path example = "example.bin";
    fs::path p = fs::current_path() / example;
    std::ofstream(p).put('a'); // create file of size 1
    std::cout << example << " size = " << fs::file_size(p) << '\n';
    fs::remove(p);

    p = argv[0];
    std::cout << p << " size = " << HumanReadable{ fs::file_size(p) } << '\n';

    try
    {
        std::cout << "Attempt to get size of a directory:\n";
        [[maybe_unused]] auto x_x = fs::file_size("/dev");
    }
    catch (fs::filesystem_error& e)
    {
        std::cout << e.what() << '\n';
    }

    for (std::error_code ec; fs::path bin : {"cat", "mouse"})
    {
        bin = "/bin" / bin;
        if (const std::uintmax_t size = fs::file_size(bin, ec); ec)
            std::cout << bin << " : " << ec.message() << '\n';
        else
            std::cout << bin << " size = " << HumanReadable{ size } << '\n';
    }
}