#include <climits>
#include <cstdlib>
#include <iostream>

int main()
{
    std::cout << std::showpos
        << "abs(+3) = " << std::abs(3) << '\n'
        << "abs(-3) = " << std::abs(-3) << '\n';

    //  std::cout << std::abs(INT_MIN); // undefined behavior on 2's complement systems
}