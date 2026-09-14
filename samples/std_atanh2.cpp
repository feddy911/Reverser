#define _CRT_SECURE_NO_WARNINGS
#include <cerrno>
#include <cfenv>
#include <cfloat>
#include <cmath>
#include <cstring>
#include <iostream>
// #pragma STDC FENV_ACCESS ON

int main()
{
    std::cout << "atanh(0) = " << std::atanh(0) << '\n'
        << "atanh(-0) = " << std::atanh(-0.0) << '\n'
        << "atanh(0.9) = " << std::atanh(0.9) << '\n';

    // error handling
    errno = 0;
    std::feclearexcept(FE_ALL_EXCEPT);

    std::cout << "atanh(-1) = " << std::atanh(-1) << '\n';

    if (errno == ERANGE)
        std::cout << "    errno == ERANGE: " << std::strerror(errno) << '\n';
    if (std::fetestexcept(FE_DIVBYZERO))
        std::cout << "    FE_DIVBYZERO raised\n";
}