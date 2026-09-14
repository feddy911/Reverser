#include <cmath>
#include <iostream>
#include <numbers>

int main()
{
    constexpr double hpi = std::numbers::pi / 2.0;

    std::cout << "E(0) = " << std::comp_ellint_2(0) << '\n'
        << "π/2 = " << hpi << '\n'
        << "E(1) = " << std::comp_ellint_2(1) << '\n'
        << "E(1, π/2) = " << std::ellint_2(1, hpi) << '\n';
}