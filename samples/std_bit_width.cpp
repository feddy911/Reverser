#include <bit>
#include <bitset>
#include <iostream>

int main()
{
    for (unsigned x{ 0 }; x != 8; ++x)
    {
        std::cout
            << "bit_width( "
            << std::bitset<4>{x} << " ) = "
            << std::bit_width(x) << '\n';
    }
}