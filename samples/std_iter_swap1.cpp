#include <algorithm>
#include <iostream>
#include <random>
#include <string_view>
#include <vector>

template<class ForwardIt>
void selection_sort(ForwardIt begin, ForwardIt end)
{
    for (ForwardIt it = begin; it != end; ++it)
        std::iter_swap(it, std::min_element(it, end));
}

void println(std::string_view rem, std::vector<int> const& v)
{
    std::cout << rem;
    for (int e : v)
        std::cout << e << ' ';
    std::cout << '\n';
}

template<int min, int max>
int rand_int()
{
    static std::uniform_int_distribution dist(min, max);
    static std::mt19937 gen(std::random_device{}());
    return dist(gen);
}

int main()
{
    std::vector<int> v;
    std::generate_n(std::back_inserter(v), 20, rand_int<-9, +9>);

    std::cout << std::showpos;
    println("Before sort: ", v);
    selection_sort(v.begin(), v.end());
    println("After sort:  ", v);
}