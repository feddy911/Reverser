#include <cmath>
#include <iostream>

int main()
{
    std::cout << "atan(1) = " << std::atan(1) << '\n'
        << "4*atan(1) = " << 4 * std::atan(1) << '\n';

    // special values
    std::cout << "atan(Inf) = " << std::atan(INFINITY) << '\n'
        << "2*atan(Inf) = " << 2 * std::atan(INFINITY) << '\n'
        << "atan(-0.0) = " << std::atan(-0.0) << '\n'
        << "atan(+0.0) = " << std::atan(0) << '\n';
}