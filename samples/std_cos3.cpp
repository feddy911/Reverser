#include <cerrno>
#include <cfenv>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numbers>

// #pragma STDC FENV_ACCESS ON

constexpr double pi = std::numbers::pi; // or std::acos(-1) before C++20

constexpr double your_cos(double x)
{
    double cos{ 1 }, pow{ x };
    for (auto fac{ 1ull }, n{ 1ull }; n != 19; fac *= ++n, pow *= x)
        if ((n & 1) == 0)
            cos += (n & 2 ? -pow : pow) / fac;
    return cos;
}

int main()
{
    std::cout << std::setprecision(10) << std::showpos
        << "Typical usage:\n"
        << "std::cos(pi/3) = " << std::cos(pi / 3) << '\n'
        << "your cos(pi/3) = " << your_cos(pi / 3) << '\n'
        << "std::cos(pi/2) = " << std::cos(pi / 2) << '\n'
        << "your cos(pi/2) = " << your_cos(pi / 2) << '\n'
        << "std::cos(-3*pi/4) = " << std::cos(-3 * pi / 4) << '\n'
        << "your cos(-3*pi/4) = " << your_cos(-3 * pi / 4) << '\n'
        << "Special values:\n"
        << "std::cos(+0) = " << std::cos(0.0) << '\n'
        << "std::cos(-0) = " << std::cos(-0.0) << '\n';

    // error handling
    std::feclearexcept(FE_ALL_EXCEPT);

    std::cout << "cos(INFINITY) = " << std::cos(INFINITY) << '\n';
    if (std::fetestexcept(FE_INVALID))
        std::cout << "    FE_INVALID raised\n";
}