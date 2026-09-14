#include <cmath>
#include <iostream>
#include <numbers>

int main()
{
    const double hpi = std::numbers::pi / 2;

    std::cout << "Π(0,0,π/2) = " << std::ellint_3(0, 0, hpi) << '\n'
        << "π/2 = " << hpi << '\n';
}