#include <algorithm>
#include <iostream>
#include <vector>

void println(auto const& v)
{
    for (auto count{ v.size() }; auto const& e : v)
        std::cout << e << (--count ? ", " : "\n");
}

int main()
{
    std::vector<int> vi{ 1, 2, 3, 4, 5 };
    println(vi);

    std::for_each_n(vi.begin(), 3, [](auto& n) { n *= 2; });
    println(vi);
}