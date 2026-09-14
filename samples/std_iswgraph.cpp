#include <clocale>
#include <cwctype>
#include <iostream>

int main()
{
    wchar_t c = L'\u2602'; // the Unicode character Umbrella ('☂')

    std::cout << std::hex << std::showbase << std::boolalpha
        << "in the default locale, iswgraph("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswgraph(c)) << '\n';

    std::setlocale(LC_ALL, "en_US.utf8");
    std::cout << "in Unicode locale, iswgraph("
        << static_cast<std::wint_t>(c) << ") = "
        << static_cast<bool>(std::iswgraph(c)) << '\n';
}