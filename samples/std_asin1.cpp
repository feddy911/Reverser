#include <cmath>
#include <complex>
#include <iostream>

int main()
{
    std::cout << std::fixed;
    std::complex<double> z1(-2.0, 0.0);
    std::cout << "asin" << z1 << " = " << std::asin(z1) << '\n';

    std::complex<double> z2(-2.0, -0.0);
    std::cout << "asin" << z2 << " (the other side of the cut) = "
        << std::asin(z2) << '\n';

    // for any z, asin(z) = acos(−z) − pi / 2
    const double pi = std::acos(-1);
    std::complex<double> z3 = std::acos(z2) - pi / 2;
    std::cout << "sin(acos" << z2 << " - pi / 2) = " << std::sin(z3) << '\n';
}