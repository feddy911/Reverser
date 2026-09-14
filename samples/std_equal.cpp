#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string_view>

constexpr bool is_palindrome(const std::string_view& s)
{
    return std::equal(s.cbegin(), s.cbegin() + s.size() / 2, s.crbegin());
}

void test(const std::string_view& s)
{
    std::cout << std::quoted(s)
        << (is_palindrome(s) ? " is" : " is not")
        << " a palindrome\n";
}

int main()
{
    test("radar");
    test("hello");
}