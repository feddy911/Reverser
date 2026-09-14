#include <bit>
#include <bitset>
#include <iostream>

int main()
{
    using bin = std::bitset<8>;

    for (unsigned x{ 0 }; x != 10; ++x)
    {
        unsigned const z = std::bit_ceil(x); // `ceil2` before P1956R1
        std::cout << "bit_ceil( " << bin(x) << " ) = " << bin(z) << '\n';
    }
}