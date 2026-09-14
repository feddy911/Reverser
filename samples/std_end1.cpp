#include <iostream>
#include <iterator>
#include <algorithm>
#include <initializer_list>

int main()
{
    std::initializer_list il = { 3, 1, 4, 1, 5, 9 };

    std::reverse_copy(std::begin(il),
        std::end(il),
        std::ostream_iterator<int>(std::cout, " "));
}