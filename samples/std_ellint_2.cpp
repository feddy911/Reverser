#include <cmath>
#include <iostream>
#include <numbers>

int main()
{
    const double hpi = std::numbers::pi / 2.0;

    std::cout << "E(0,π/2)  = " << std::ellint_2(0, hpi) << '\n'
        << "E(0,-π/2) = " << std::ellint_2(0, -hpi) << '\n'
        << "π/2       = " << hpi << '\n'
        << "E(0.7,0)  = " << std::ellint_2(0.7, 0) << '\n'
        << "E(1,π/2)  = " << std::ellint_2(1, hpi) << '\n';
}