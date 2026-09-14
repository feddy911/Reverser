#include <iostream>

int main()
{
    for (int i = 0; i < 10; ++i)
    {
        if (i != 5)
            continue;
        std::cout << i << ' ';      // this statement is skipped each time i != 5
    }
    std::cout << '\n';

    for (int j = 0; 2 != j; ++j)
        for (int k = 0; k < 5; ++k) // only this loop is affected by continue
        {
            if (k == 3)
                continue;
            // this statement is skipped each time k == 3:
            std::cout << '(' << j << ',' << k << ") ";
        }
    std::cout << '\n';
}