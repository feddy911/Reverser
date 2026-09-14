#include <clocale>
#include <cwctype>
#include <iostream>

void demo_iswprint(std::string_view rem, const std::wint_t c)
{
    std::cout << std::boolalpha << std::hex << std::showbase
        << rem << "iswprint('" << c << "') = "
        << !!std::iswprint(c) << '\n';
}

int main()
{
    const wchar_t c1 = L'\u2002'; // en-space
    const wchar_t c2 = L'\u0082'; // break permitted

    demo_iswprint("In default locale:\n", c1);

    std::setlocale(LC_ALL, "en_US.utf8");
    demo_iswprint("In Unicode locale:\n", c1);
    demo_iswprint("", c2);
}