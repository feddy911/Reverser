#include <format>
#include <iostream>
#include <string_view>

int main()
{
    char buffer[64];

    {
        const auto result =
            std::format_to_n(
                buffer, 23,
                "Hubble's H{2} {3} {0}{4}{1} km/sec/Mpc.", // 24 bytes w/o formatters
                71,       // {0}, occupies 2 bytes
                8,        // {1}, occupies 1 byte
                "\u2080", // {2}, occupies 3 bytes, '₀' (SUBSCRIPT ZERO)
                "\u2245", // {3}, occupies 3 bytes, '≅' (APPROXIMATELY EQUAL TO)
                "\u00B1"  // {4}, occupies 2 bytes, '±' (PLUS-MINUS SIGN)
            ); // 24 + 2 + 1 + 3 + 3 + 2 == 35, no trailing '\0'

        *result.out = '\0'; // adds terminator to buffer

        const std::string_view str{ buffer, result.out }; // uses C++20 constructor

        std::cout << "Buffer until '\\0': \"" << str << "\"\n"
            << "result.out offset: " << result.out - buffer << '\n'
            << "Untruncated output size: " << result.size << "\n\n";
    }
}