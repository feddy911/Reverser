#include <iostream>
#include <map>

void print(auto rem, auto const& container)
{
    std::cout << rem << '{';
    for (char sep[]{ 0, ' ', 0 }; const auto & [key, value] : container)
        std::cout << sep << '{' << key << ", " << value << '}', * sep = ',';
    std::cout << "}\n";
}

int main()
{
    std::map<int, char> data
    {
        {1, 'a'}, {2, 'b'}, {3, 'c'}, {4, 'd'},
        {5, 'e'}, {4, 'f'}, {5, 'g'}, {5, 'g'},
    };
    print("Original:\n", data);

    const auto count = std::erase_if(data, [](const auto& item)
        {
            auto const& [key, value] = item;
            return (key & 1) == 1;
        });

    print("Erase items with odd keys:\n", data);
    std::cout << count << " items removed.\n";
}