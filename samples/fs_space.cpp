#include <cstdint>
#include <filesystem>
#include <iostream>

void print_space_info(auto const& dirs, int width = 15)
{
    (std::cout << std::left).imbue(std::locale("en_US.UTF-8"));
    for (const auto s : { "Capacity", "Free", "Available", "Dir" })
        std::cout << "│ " << std::setw(width) << s << ' ';
    for (std::cout << '\n'; auto const& dir : dirs)
    {
        std::error_code ec;
        const std::filesystem::space_info si = std::filesystem::space(dir, ec);
        for (auto x : { si.capacity, si.free, si.available })
            std::cout << "│ " << std::setw(width) << static_cast<std::intmax_t>(x) << ' ';
        std::cout << "│ " << dir << '\n';
    }
}

int main()
{
    const auto dirs = { "/dev/null", "/tmp", "/home", "/proc", "/null" };
    print_space_info(dirs);
}