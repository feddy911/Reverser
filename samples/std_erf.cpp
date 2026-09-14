#include <cmath>
#include <iomanip>
#include <iostream>

double phi(double x1, double x2)
{
    return (std::erf(x2 / std::sqrt(2)) - std::erf(x1 / std::sqrt(2))) / 2;
}

int main()
{
    std::cout << "Normal variate probabilities:\n"
        << std::fixed << std::setprecision(2);
    for (int n = -4; n < 4; ++n)
        std::cout << '[' << std::setw(2) << n
        << ':' << std::setw(2) << n + 1 << "]: "
        << std::setw(5) << 100 * phi(n, n + 1) << "%\n";

    std::cout << "Special values:\n"
        << "erf(-0) = " << std::erf(-0.0) << '\n'
        << "erf(Inf) = " << std::erf(INFINITY) << '\n';
}