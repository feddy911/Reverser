#include <algorithm>
#include <array>
#include <iostream>

int main()
{
    const auto v = { 1, 2, 3, 4 };

    for (const int n : {3, 5})
        (std::find(v.begin(), v.end(), n) == std::end(v))
        ? std::cout << "v does not contain " << n << '\n'
        : std::cout << "v contains " << n << '\n';

    auto is_even = [](int i) { return i % 2 == 0; };

    for (auto const& w : { std::array{3, 1, 4}, std::array{1, 3, 5} })
        if (auto it = std::find_if(begin(w), end(w), is_even); it != std::end(w))
            std::cout << "w contains an even number " << *it << '\n';
        else
            std::cout << "w does not contain even numbers\n";
}