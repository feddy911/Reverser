#include <cmath>
#include <iostream>

int main()
{
    std::cout << std::showpos
        << "copysign(1.0,+2.0) = " << std::copysign(1.0, +2.0) << '\n'
        << "copysign(1.0,-2.0) = " << std::copysign(1.0, -2.0) << '\n'
        << "copysign(inf,-2.0) = " << std::copysign(INFINITY, -2.0) << '\n'
        << "copysign(NaN,-2.0) = " << std::copysign(NAN, -2.0) << '\n';
}