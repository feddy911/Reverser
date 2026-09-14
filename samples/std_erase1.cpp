#include <iomanip>
#include <iostream>
#include <string>

int main()
{
    std::string word{ "startling" };
    std::cout << "Initially, word = " << std::quoted(word) << '\n';

    std::erase(word, 'l');
    std::cout << "After erase 'l': " << std::quoted(word) << '\n';

    auto erased = std::erase_if(word, [](char x)
        {
            return x == 'a' or x == 'r' or x == 't';
        });

    std::cout << "After erase all 'a', 'r', and 't': " << std::quoted(word) << '\n';
    std::cout << "Erased symbols count: " << erased << '\n';
}