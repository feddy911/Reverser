#define _CRT_SECURE_NO_WARNINGS
#include <cerrno>
#include <cfenv>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <numbers>

// #pragma STDC FENV_ACCESS ON

consteval double approx_e()
{
    long double e{ 1.0 };
    for (auto fac{ 1ull }, n{ 1llu }; n != 18; ++n, fac *= n)
        e += 1.0 / fac;
    return e;
}

int main()
{
    std::cout << std::setprecision(16)
        << "exp(1) = e¹ = " << std::exp(1) << '\n'
        << "numbers::e  = " << std::numbers::e << '\n'
        << "approx_e    = " << approx_e() << '\n'
        << "FV of $100, continuously compounded at 3% for 1 year = "
        << std::setprecision(6) << 100 * std::exp(0.03) << '\n';

    // special values
    std::cout << "exp(-0) = " << std::exp(-0.0) << '\n'
        << "exp(-Inf) = " << std::exp(-INFINITY) << '\n';

    // error handling 
    errno = 0;
    std::feclearexcept(FE_ALL_EXCEPT);

    std::cout << "exp(710) = " << std::exp(710) << '\n';

    if (errno == ERANGE)
        std::cout << "    errno == ERANGE: " << std::strerror(errno) << '\n';
    if (std::fetestexcept(FE_OVERFLOW))
        std::cout << "    FE_OVERFLOW raised\n";
}