#include <cctype>
#include <climits>
#include <iostream>

int main()
{
    for (int c = 0; UCHAR_MAX >= c; ++c)
        if (isxdigit(c))
            std::cout << static_cast<char>(c);
    std::cout << '\n';
}