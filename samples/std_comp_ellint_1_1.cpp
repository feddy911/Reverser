#include <cmath>
#include <iostream>
#include <numbers>

int main()
{
    constexpr double π{ std::numbers::pi };

    std::cout << "K(0) ≈ " << std::comp_ellint_1(0) << '\n'
        << "π/2 ≈ " << π / 2 << '\n'
        << "K(0.5) ≈ " << std::comp_ellint_1(0.5) << '\n'
        << "F(0.5, π/2) ≈ " << std::ellint_1(0.5, π / 2) << '\n'
        << "The period of a pendulum length 1m at 10° initial angle ≈ "
        << 4 * std::sqrt(1 / 9.80665) * std::comp_ellint_1(std::sin(π / 18 / 2))
        << "s,\n" "whereas the linear approximation gives ≈ "
        << 2 * π * std::sqrt(1 / 9.80665) << '\n';
}