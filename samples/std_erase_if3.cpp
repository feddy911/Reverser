#include <iostream>
#include <set>

void print(auto rem, auto const& container)
{
    std::cout << rem << '{';
    for (char sep[]{ 0, ' ', 0 }; const auto & item : container)
        std::cout << sep << item, * sep = ',';
    std::cout << "}\n";
}

int main()
{
    std::multiset data{ 3, 3, 4, 5, 5, 6, 6, 7, 2, 1, 0 };
    print("Original:\n", data);

    auto divisible_by_3 = [](auto const& x) { return (x % 3) == 0; };

    const auto count = std::erase_if(data, divisible_by_3);

    print("Erase all items divisible by 3:\n", data);
    std::cout << count << " items erased.\n";
}