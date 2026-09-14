#include <functional>
#include <iostream>
#include <iterator>
#include <numeric>
#include <vector>

int main()
{
    std::vector data{ 3, 1, 4, 1, 5, 9, 2, 6 };

    std::cout << "Exclusive sum: ";
    std::exclusive_scan(data.begin(), data.end(),
        std::ostream_iterator<int>(std::cout, " "),
        0);
    std::cout << "\nInclusive sum: ";
    std::inclusive_scan(data.begin(), data.end(),
        std::ostream_iterator<int>(std::cout, " "));

    std::cout << "\n\nExclusive product: ";
    std::exclusive_scan(data.begin(), data.end(),
        std::ostream_iterator<int>(std::cout, " "),
        1, std::multiplies<>{});
    std::cout << "\nInclusive product: ";
    std::inclusive_scan(data.begin(), data.end(),
        std::ostream_iterator<int>(std::cout, " "),
        std::multiplies<>{});
}