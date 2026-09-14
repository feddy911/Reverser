#include <cmath>
#include <complex>
#include <iostream>

int main()
{
	const double pi = std::acos(-1.0);
	const std::complex<double> i(0.0, 1.0);

	std::cout << std::fixed << " exp(i * pi) = " << std::exp(i * pi) << '\n';
}