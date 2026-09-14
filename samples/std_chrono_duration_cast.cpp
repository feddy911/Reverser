#include <chrono>
#include <iostream>
#include <ratio>
#include <thread>

void f()
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

int main()
{
    const auto t1 = std::chrono::high_resolution_clock::now();
    f();
    const auto t2 = std::chrono::high_resolution_clock::now();

    // floating-point duration: no duration_cast needed
    const std::chrono::duration<double, std::milli> fp_ms = t2 - t1;

    // integral duration: requires duration_cast
    const auto int_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    // converting integral duration to integral duration of
    // shorter divisible time unit: no duration_cast needed
    const std::chrono::duration<long, std::micro> int_usec = int_ms;

    std::cout << "f() took " << fp_ms << ", or "
        << int_ms << " (whole milliseconds), or "
        << int_usec << " (whole microseconds)\n";
}