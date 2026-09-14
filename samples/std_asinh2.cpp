#include <cmath>
#include <iostream>

int main()
{
    std::cout << "asinh(1) = " << std::asinh(1) << '\n'
        << "asinh(-1) = " << std::asinh(-1) << '\n';

    // special values
    std::cout << "asinh(+0) = " << std::asinh(+0.0) << '\n'
        << "asinh(-0) = " << std::asinh(-0.0) << '\n';
}