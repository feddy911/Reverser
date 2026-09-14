#include <cmath>
#include <iostream>

#define SHOW_UNORDERED(x, y) \
    std::cout << std::boolalpha << "isunordered(" \
              << #x << ", " << #y << "): " \
              << std::isunordered(x, y) << '\n'

int main()
{
    SHOW_UNORDERED(10, 01);
    SHOW_UNORDERED(INFINITY, NAN);
    SHOW_UNORDERED(INFINITY, INFINITY);
    SHOW_UNORDERED(NAN, NAN);
}