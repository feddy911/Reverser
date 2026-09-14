#define _CRT_SECURE_NO_WARNINGS
#include <cstdlib>
#include <iostream>

int main()
{
    if (const char* env_p = std::getenv("PATH"))
        std::cout << "Your PATH is: " << env_p << '\n';
}