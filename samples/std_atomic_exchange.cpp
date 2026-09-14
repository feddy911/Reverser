#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

std::atomic<bool> lock(false); // holds true when locked
                               // holds false when unlocked

int new_line{ 1 }; // the access is synchronized via atomic lock variable

void f(int n)
{
    for (int cnt = 0; cnt < 100; ++cnt)
    {
        while (std::atomic_exchange_explicit(&lock, true, std::memory_order_acquire))
            ; // spin until acquired
        std::cout << n << (new_line++ % 80 ? "" : "\n");
        std::atomic_store_explicit(&lock, false, std::memory_order_release);
    }
}

int main()
{
    std::vector<std::thread> v;
    for (int n = 0; n < 8; ++n)
        v.emplace_back(f, n);
    for (auto& t : v)
        t.join();
}