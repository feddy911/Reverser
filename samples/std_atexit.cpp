#include <cstdlib>
#include <iostream>

void atexit_handler_1()
{
    std::cout << "At exit #1\n";
}

void atexit_handler_2()
{
    std::cout << "At exit #2\n";
}

int main()
{
    const int result_1 = std::atexit(atexit_handler_1);
    const int result_2 = std::atexit(atexit_handler_2);

    if (result_1 || result_2)
    {
        std::cerr << "Registration failed!\n";
        return EXIT_FAILURE;
    }

    std::cout << "Returning from main...\n";
    return EXIT_SUCCESS;
}