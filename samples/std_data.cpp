#define _CRT_SECURE_NO_WARNINGS
#include <cstring>
#include <iostream>
#include <string>

int main()
{
    std::string s{ "Hello world!\n" };

    char a[20]; // storage for a C-style string
    std::strcpy(a, std::data(s));
    //  [s.data(), s.data() + s.size()] is guaranteed to be an NTBS since C++11

    std::cout << a;
}