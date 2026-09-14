#include <cmath>
#include <iostream>
#include <numbers>

int main()
{
    const double hpi = std::numbers::pi / 2.0;

    std::cout << "F(0,π/2)  = " << std::ellint_1(0, hpi) << '\n'
        << "F(0,-π/2) = " << std::ellint_1(0, -hpi) << '\n'
        << "π/2       = " << hpi << '\n'
        << "F(0.7,0)  = " << std::ellint_1(0.7, 0) << '\n';
}