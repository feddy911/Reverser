#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

void print(auto const& rem, auto const& v)
{
    std::cout << rem << '[' << size(v) << "] {";
    for (char comma[]{ 0, 0 }; auto const& s : v)
        std::cout << comma << ' ' << std::quoted(s), comma[0] = ',';
    std::cout << " }\n";
}

int main()
{
    std::vector<std::string> p{ "Alpha", "Bravo", "Charlie" }, q;

    print("p", p), print("q", q);

    using RI = std::reverse_iterator<std::vector<std::string>::iterator>;

    for (RI iter{ p.rbegin() }, rend{ p.rend() }; iter != rend; ++iter)
        q.emplace_back(/* ADL */ iter_move(iter));

    print("p", p), print("q", q);
}