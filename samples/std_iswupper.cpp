#include <clocale>
#include <cwctype>
#include <iostream>

int main()
{
    const wchar_t c = L'\u053d'; // Armenian capital letter xeh ('Խ')

    std::cout << std::hex << std::showbase << std::boolalpha;
    std::cout << "in the default locale, iswupper("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswupper(c)) << '\n';

    std::setlocale(LC_ALL, "en_US.utf8");
    std::cout << "in Unicode locale, iswupper("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswupper(c)) << '\n';
}