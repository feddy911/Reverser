#include <algorithm>
#include <iostream>
#include <valarray>

void show(const std::valarray<int>& v)
{
    std::for_each(std::begin(v), std::end(v), [](int c)
        {
            std::cout << c << ' ';
        });
    std::cout << '\n';
};

int main()
{
    const std::valarray<int> x{ 47, 70, 37, 52, 90, 23, 17, 33, 22, 16, 21, 4 };
    const std::valarray<int> y{ 25, 31, 71, 56, 21, 21, 15, 34, 21, 27, 12, 6 };

    show(x);
    show(y);

    const std::valarray<int> z{ x + y };

    for (char c : z)
        std::cout << c;
}