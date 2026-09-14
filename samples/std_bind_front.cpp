#include <cassert>
#include <functional>

int minus(int a, int b)
{
    return a - b;
}

struct S
{
    int val;
    int minus(int arg) const noexcept { return val - arg; }
};

int main()
{
    auto fifty_minus = std::bind_front(minus, 50);
    assert(fifty_minus(3) == 47); // equivalent to: minus(50, 3) == 47

    auto member_minus = std::bind_front(&S::minus, S{ 50 });
    assert(member_minus(3) == 47); //: S tmp{50}; tmp.minus(3) == 47

    // Noexcept-specification is preserved:
    static_assert(!noexcept(fifty_minus(3)));
    static_assert(noexcept(member_minus(3)));

    // Binding of a lambda:
    auto plus = [](int a, int b) { return a + b; };
    auto forty_plus = std::bind_front(plus, 40);
    assert(forty_plus(7) == 47); // equivalent to: plus(40, 7) == 47

#if __cpp_lib_bind_front >= 202306L
    auto fifty_minus_cpp26 = std::bind_front<minus>(50);
    assert(fifty_minus_cpp26(3) == 47);

    auto member_minus_cpp26 = std::bind_front<&S::minus>(S{ 50 });
    assert(member_minus_cpp26(3) == 47);

    auto forty_plus_cpp26 = std::bind_front<plus>(40);
    assert(forty_plus(7) == 47);
#endif

#if __cpp_lib_bind_back >= 202202L
    auto madd = [](int a, int b, int c) { return a * b + c; };
    auto mul_plus_seven = std::bind_back(madd, 7);
    assert(mul_plus_seven(4, 10) == 47); //: madd(4, 10, 7) == 47
#endif

#if __cpp_lib_bind_back >= 202306L
    auto mul_plus_seven_cpp26 = std::bind_back<madd>(7);
    assert(mul_plus_seven_cpp26(4, 10) == 47);
#endif
}