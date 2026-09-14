#include <chrono>
#include <iostream>

int main() {
    const std::chrono::zoned_time cur_time{ std::chrono::current_zone(),
                                            std::chrono::system_clock::now() };
    std::cout << cur_time << '\n';
}