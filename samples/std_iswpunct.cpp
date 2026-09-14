#include <clocale>
#include <cwctype>
#include <iostream>

int main()
{
    wchar_t c = L'\u2051'; // Two asterisks ('⁑')

    std::cout << std::hex << std::showbase << std::boolalpha
        << "in the default locale, iswpunct("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswpunct(c)) << '\n';

    std::setlocale(LC_ALL, "en_US.utf8");
    std::cout << "in Unicode locale, iswpunct("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswpunct(c)) << '\n';
}