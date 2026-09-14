#include <cfloat>
#include <cmath>
#include <iostream>
#include <limits>

int main()
{
    const double max = std::numeric_limits<double>::max();
    const double inf = std::numeric_limits<double>::infinity();

    std::cout << std::boolalpha
        << "isinf(NaN) = " << std::isinf(NAN) << '\n'
        << "isinf(Inf) = " << std::isinf(INFINITY) << '\n'
        << "isinf(max) = " << std::isinf(max) << '\n'
        << "isinf(inf) = " << std::isinf(inf) << '\n'
        << "isinf(0.0) = " << std::isinf(0.0) << '\n'
        << "isinf(exp(800)) = " << std::isinf(std::exp(800)) << '\n'
        << "isinf(DBL_MIN/2.0) = " << std::isinf(DBL_MIN / 2.0) << '\n';
}