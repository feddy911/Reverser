#include <bit>
#include <bitset>
#include <cmath>
#include <iostream>

int main()
{
    for (auto u = 0u; u != 10; ++u)
    {
        std::cout << "u = " << u << " = " << std::bitset<4>(u);
        if (std::has_single_bit(u)) // `ispow2` before P1956R1
            std::cout << " = 2^" << std::log2(u) << " (is power of two)";
        std::cout << '\n';
    }
}