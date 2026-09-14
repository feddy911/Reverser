#include <numeric>

int main()
{
    constexpr int p{ 2 * 2 * 3 };
    constexpr int q{ 2 * 3 * 3 };
    static_assert(2 * 3 == std::gcd(p, q));

    static_assert(std::gcd(6, 10) == 2);
    static_assert(std::gcd(6, -10) == 2);
    static_assert(std::gcd(-6, -10) == 2);

    static_assert(std::gcd(24, 0) == 24);
    static_assert(std::gcd(-24, 0) == 24);
}