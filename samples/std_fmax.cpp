#include <cmath>
#include <iostream>

int main()
{
    std::cout << "fmax(2,1)    = " << std::fmax(2, 1) << '\n'
        << "fmax(-Inf,0) = " << std::fmax(-INFINITY, 0) << '\n'
        << "fmax(NaN,-1) = " << std::fmax(NAN, -1) << '\n';
}