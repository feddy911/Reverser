// samples/FibTimer.cpp
// Iterative Fibonacci + chrono; exercises numeric loops and iostream.
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

static std::uint64_t fib_iter(unsigned n) {
    if (n == 0) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }
    std::uint64_t a = 0;
    std::uint64_t b = 1;
    for (unsigned i = 2; i <= n; ++i) {
        const std::uint64_t c = a + b;
        a = b;
        b = c;
    }
    return b;
}

static std::vector<std::uint64_t> fib_series(unsigned n) {
    std::vector<std::uint64_t> out;
    out.reserve(n + 1);
    for (unsigned i = 0; i <= n; ++i) {
        out.push_back(fib_iter(i));
    }
    return out;
}

static void print_series(const std::vector<std::uint64_t>& s) {
    std::cout << "Series:";
    for (auto v : s) {
        std::cout << ' ' << v;
    }
    std::cout << "\n";
}

int main(int argc, char** argv) {
    unsigned n = 20;
    if (argc >= 2) {
        n = static_cast<unsigned>(std::strtoul(argv[1], nullptr, 10));
        if (n > 90) {
            n = 90;
        }
    }

    std::cout << "=== FibTimer ===\n";
    std::cout << "n=" << n << "\n";

    const auto t0 = std::chrono::steady_clock::now();
    const auto series = fib_series(n);
    const auto t1 = std::chrono::steady_clock::now();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    print_series(series);
    std::cout << "fib(n)=" << series.back() << "\n";
    std::cout << "elapsed_us=" << us << "\n";
    return 0;
}
