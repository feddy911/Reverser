#include <cassert>
#include <cmath>
#include <iostream>
#include <numbers>

const double π = std::numbers::pi; // or std::acos(-1) in pre C++20

// To calculate the cylindrical Neumann function via cylindrical Bessel function of the
// first kind we have to implement J, because the direct invocation of the
// std::cyl_bessel_j(nu, x), per formula above,
// for negative nu raises 'std::domain_error': Bad argument in __cyl_bessel_j.

double J_neg(double nu, double x)
{
    return std::cos(-nu * π) * std::cyl_bessel_j(-nu, x)
        - std::sin(-nu * π) * std::cyl_neumann(-nu, x);
}

double J_pos(double nu, double x)
{
    return std::cyl_bessel_j(nu, x);
}

double J(double nu, double x)
{
    return nu < 0.0 ? J_neg(nu, x) : J_pos(nu, x);
}

int main()
{
    std::cout << "spot checks for nu == 0.5\n" << std::fixed << std::showpos;
    const double nu = 0.5;
    for (double x = 0.0; x <= 2.0; x += 0.333)
    {
        const double n = std::cyl_neumann(nu, x);
        const double j = (J(nu, x) * std::cos(nu * π) - J(-nu, x)) / std::sin(nu * π);
        std::cout << "N_.5(" << x << ") = " << n << ", calculated via J = " << j << '\n';
        assert(n == j);
    }
}