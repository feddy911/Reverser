#define _CRT_SECURE_NO_WARNINGS
#include <cerrno>
#include <cfenv>
#include <cfloat>
#include <cmath>
#include <cstring>
#include <iostream>

// #pragma STDC FENV_ACCESS ON

struct Point3D { float x, y, z; };

int main()
{
    // typical usage
    std::cout << "(1,1) cartesian is (" << std::hypot(1, 1)
        << ',' << std::atan2(1, 1) << ") polar\n";

    Point3D a{ 3.14, 2.71, 9.87 }, b{ 1.14, 5.71, 3.87 };
    // C++17 has 3-argument hypot overload:
    std::cout << "distance(a,b) = "
        << std::hypot(a.x - b.x, a.y - b.y, a.z - b.z) << '\n';

    // special values
    std::cout << "hypot(NAN,INFINITY) = " << std::hypot(NAN, INFINITY) << '\n';

    // error handling
    errno = 0;
    std::feclearexcept(FE_ALL_EXCEPT);
    std::cout << "hypot(DBL_MAX,DBL_MAX) = " << std::hypot(DBL_MAX, DBL_MAX) << '\n';

    if (errno == ERANGE)
        std::cout << "    errno = ERANGE " << std::strerror(errno) << '\n';
    if (std::fetestexcept(FE_OVERFLOW))
        std::cout << "    FE_OVERFLOW raised\n";
}