#include <chrono>
#include <iostream>

template<typename Diff>
void log_progress(Diff d)
{
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(d)
        << " passed" << std::endl;
}

int main()
{
    std::cout.sync_with_stdio(false); // on some platforms, stdout flushes on \n

    static volatile int sink{};
    const auto t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 5; ++i)
    {
        for (int j = 0; j < 10000; ++j)
            for (int k = 0; k < 20000; ++k)
                sink += i * j * k; // do some work
        log_progress(std::chrono::high_resolution_clock::now() - t1);
    }
}