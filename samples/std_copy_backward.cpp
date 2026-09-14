#include <algorithm>
#include <iostream>
#include <numeric>
#include <vector>

int main()
{
    std::vector<int> source(4);
    std::iota(source.begin(), source.end(), 1); // fills with 1, 2, 3, 4

    std::vector<int> destination(6);

    std::copy_backward(source.begin(), source.end(), destination.end());

    std::cout << "destination contains: ";
    for (auto i : destination)
        std::cout << i << ' ';
    std::cout << '\n';
}