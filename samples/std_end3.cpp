#include <algorithm>
#include <iostream>
#include <vector>

int main()
{
    std::vector<int> v = { 3, 1, 4 };
    if (std::find(std::begin(v), std::end(v), 5) != std::end(v))
        std::cout << "Found a 5 in vector v!\n";

    int w[] = { 5, 10, 15 };
    if (std::find(std::begin(w), std::end(w), 5) != std::end(w))
        std::cout << "Found a 5 in array w!\n";
}