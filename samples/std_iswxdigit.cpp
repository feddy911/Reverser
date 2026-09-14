#include <cwctype>
#include <iostream>

int main()
{
    std::cout << std::boolalpha
        << (std::iswxdigit(L'a') != 0) << ' '
        << (std::iswxdigit(L'ä') != 0) << '\n';
}