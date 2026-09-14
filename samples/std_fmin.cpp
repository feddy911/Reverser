#include <cmath>
#include <iostream>

int main()
{
    std::cout << "fmin(2,1)    = " << std::fmin(2, 1) << '\n'
        << "fmin(-Inf,0) = " << std::fmin(-INFINITY, 0) << '\n'
        << "fmin(NaN,-1) = " << std::fmin(NAN, -1) << '\n';
}