#include <complex>
#include <iostream>

int main()
{
    std::complex<double> z1(1, 0);
    std::complex<double> z2(0, 0);
    std::complex<double> z3(0, 1);
    std::complex<double> z4(-1, 0);
    std::complex<double> z5(-1, -0.0);
    double f = 1.;
    int i = -1;

    std::cout << "phase angle of " << z1 << " is " << std::arg(z1) << '\n'
        << "phase angle of " << z2 << " is " << std::arg(z2) << '\n'
        << "phase angle of " << z3 << " is " << std::arg(z3) << '\n'
        << "phase angle of " << z4 << " is " << std::arg(z4) << '\n'
        << "phase angle of " << z5 << " is " << std::arg(z5) << " "
        "(the other side of the cut)\n"
        << "phase angle of " << f << " is " << std::arg(f) << '\n'
        << "phase angle of " << i << " is " << std::arg(i) << '\n';

}