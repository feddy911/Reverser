#include <compare>
#include <iostream>

// does not support <=>
struct Rational_1
{
    int num;
    int den; // > 0
};

inline constexpr bool operator<(Rational_1 lhs, Rational_1 rhs)
{
    return lhs.num * rhs.den < rhs.num* lhs.den;
}

inline constexpr bool operator==(Rational_1 lhs, Rational_1 rhs)
{
    return lhs.num * rhs.den == rhs.num * lhs.den;
}

// supports <=>
struct Rational_2
{
    int num;
    int den; // > 0
};

inline constexpr std::weak_ordering operator<=>(Rational_2 lhs, Rational_2 rhs)
{
    return lhs.num * rhs.den <=> rhs.num * lhs.den;
}

inline constexpr bool operator==(Rational_2 lhs, Rational_2 rhs)
{
    return lhs <=> rhs == 0;
}

void print(int id, std::weak_ordering value)
{
    std::cout << id << ") ";
    if (value == 0)
        std::cout << "equal\n";
    else if (value < 0)
        std::cout << "less\n";
    else
        std::cout << "greater\n";
}

int main()
{
    Rational_1 a{ 1, 2 }, b{ 3, 4 };
    //  print(1, a <=> b); // does not work
    print(2, std::compare_weak_order_fallback(a, b)); // works, defaults to < and ==

    Rational_2 c{ 6, 5 }, d{ 8, 7 };
    print(3, c <=> d); // works
    print(4, std::compare_weak_order_fallback(c, d)); // works

    Rational_2 e{ 2, 3 }, f{ 4, 6 };
    print(5, e <=> f); // works
    print(6, std::compare_weak_order_fallback(e, f)); // works
}