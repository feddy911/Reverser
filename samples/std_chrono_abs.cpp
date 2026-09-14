#include <chrono>
#include <iostream>

int main()
{
    using namespace std::chrono;

    static_assert(abs(-42s) == std::chrono::abs(42s));

    std::cout << "abs(+3min) = " << abs(3min).count() << '\n'
        << "abs(-3min) = " << abs(-3min).count() << '\n';
}