#include <iostream>

int main()
{
    int i = 2;
    switch (i)
    {
    case 1: std::cout << "1";   // <---- maybe warning: fall through
    case 2: std::cout << "2";   // execution starts at this case label (+warning)
    case 3: std::cout << "3";   // <---- maybe warning: fall through
    case 4:                     // <---- maybe warning: fall through
    case 5: std::cout << "45";  //
        break;              // execution of subsequent statements is terminated
    case 6: std::cout << "6";
    }
    std::cout << '\n';

    for (char c = 'a'; c < 'c'; c++)
    {
        for (int i = 0; i < 5; i++)      // only this loop is affected by break
        {                                //
            if (i == 2)                  //
                break;                   //
            std::cout << c << i << ' ';  //
        }
    }
    std::cout << '\n';
}