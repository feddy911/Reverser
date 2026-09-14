#include <cmath>
#include <iomanip>
#include <iostream>

double normalCDF(double x) // Phi(-∞, x) aka N(x)
{
    return std::erfc(-x / std::sqrt(2)) / 2;
}

int main()
{
    std::cout << "normal cumulative distribution function:\n"
        << std::fixed << std::setprecision(2);
    for (double n = 0; n < 1; n += 0.1)
        std::cout << "normalCDF(" << n << ") = " << 100 * normalCDF(n) << "%\n";

    std::cout << "special values:\n"
        << "erfc(-Inf) = " << std::erfc(-INFINITY) << '\n'
        << "erfc(Inf) = " << std::erfc(INFINITY) << '\n';
}