#include <complex>
#include <iostream>

int main()
{
    std::complex<double> z(1.0, 2.0);
    std::cout << "The conjugate of " << z << " is " << std::conj(z) << '\n'
        << "Their product is " << z * std::conj(z) << '\n';
}