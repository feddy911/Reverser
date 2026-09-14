#include <cassert>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <numbers>
#include <string>

long binom_via_beta(int n, int k)
{
    return std::lround(1 / ((n + 1) * std::beta(n - k + 1, k + 1)));
}

long binom_via_gamma(int n, int k)
{
    return std::lround(std::tgamma(n + 1) /
        (std::tgamma(n - k + 1) *
            std::tgamma(k + 1)));
}

int main()
{
    std::cout << "Pascal's triangle:\n";
    for (int n = 1; n < 10; ++n)
    {
        std::cout << std::string(20 - n * 2, ' ');
        for (int k = 1; k < n; ++k)
        {
            std::cout << std::setw(3) << binom_via_beta(n, k) << ' ';
            assert(binom_via_beta(n, k) == binom_via_gamma(n, k));
        }
        std::cout << '\n';
    }

    // A spot-check
    const long double p = 0.123; // a random value in [0, 1]
    const long double q = 1 - p;
    const long double π = std::numbers::pi_v<long double>;
    std::cout << "\n\n" << std::setprecision(19)
        << "β(p,1-p)   = " << std::beta(p, q) << '\n'
        << "π/sin(π*p) = " << π / std::sin(π * p) << '\n';
}