#include <iostream>
#include <sstream>

int main()
{
    // boolalpha output
    std::cout << "default true: " << true << '\n'
        << "default false: " << false << '\n'
        << std::boolalpha
        << "boolalpha true: " << true << '\n'
        << "boolalpha false: " << false << '\n'
        << std::noboolalpha
        << "noboolalpha true: " << true << '\n'
        << "noboolalpha false: " << false << '\n';

    // boolalpha parse
    bool b1, b2;
    std::istringstream is("true false");
    is >> std::boolalpha >> b1 >> b2;

    std::cout << '"' << is.str() << "\" parsed as: "
        << std::boolalpha << b1 << ' ' << b2 << '\n';
}