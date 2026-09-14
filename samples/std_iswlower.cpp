#include <clocale>
#include <cwctype>
#include <iostream>

int main()
{
    wchar_t c = L'\u0444'; // Cyrillic small letter ef ('ф')

    std::cout << std::hex << std::showbase << std::boolalpha
        << "in the default locale, iswlower("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswlower(c)) << '\n';

    std::setlocale(LC_ALL, "en_US.utf8");
    std::cout << "in Unicode locale, iswlower("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswlower(c)) << '\n';
}