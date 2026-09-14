#include <iostream>
#include <locale>

int main()
{
    const wchar_t c = L'\u03c0'; // GREEK SMALL LETTER PI

    std::locale loc1("C");
    std::cout << std::boolalpha
        << "islower('π', C locale) returned "
        << std::islower(c, loc1) << '\n'
        << "isupper('π', C locale) returned "
        << std::isupper(c, loc1) << '\n';

    std::locale loc2("en_US.UTF8");
    std::cout << "islower('π', Unicode locale) returned "
        << std::islower(c, loc2) << '\n'
        << "isupper('π', Unicode locale) returned "
        << std::isupper(c, loc2) << '\n';
}