#include <iostream>
#include <locale>

int main()
{
    const wchar_t c = L'\u00de'; // LATIN CAPITAL LETTER THORN

    std::locale loc1("C");
    std::cout << std::boolalpha
        << "isupper('Þ', C locale) returned " << std::isupper(c, loc1) << '\n'
        << "islower('Þ', C locale) returned " << std::islower(c, loc1) << '\n';

    std::locale loc2("en_US.UTF8");
    std::cout << "isupper('Þ', Unicode locale) returned "
        << std::isupper(c, loc2) << '\n'
        << "islower('Þ', Unicode locale) returned "
        << std::islower(c, loc2) << '\n';
}