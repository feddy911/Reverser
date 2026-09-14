#include <iostream>
#include <locale>
#include <string>
#include <unordered_set>

struct gxdigit_ctype : std::ctype<wchar_t>
{
    std::unordered_set<wchar_t> greek_digits{ L'α', L'β', L'γ', L'δ', L'ε', L'ζ' };

    bool do_is(mask m, char_type c) const override
    {
        return (m & xdigit) && greek_digits.contains(c)
            ? true // 6 first Greek small letters will be classified as digits
            : ctype::do_is(m, c); // leave the rest to the parent class
    }
};

int main()
{
    std::wstring text = L"0123456789abcdefABCDEFαβγδεζηθικλμ";
    std::locale loc(std::locale(""), new gxdigit_ctype);

    std::locale::global(std::locale("en_US.utf8"));
    std::wcout.imbue(std::locale());

    std::wcout << "Hexadecimal digits in text: ";
    for (const wchar_t c : text)
        if (std::isxdigit(c, loc))
            std::wcout << c << L' ';
    std::wcout << L'\n';

    std::wcout << "Not hexadecimal digits in text: ";
    for (const wchar_t c : text)
        if (not std::isxdigit(c, loc))
            std::wcout << c << L' ';
    std::wcout << L'\n';
}