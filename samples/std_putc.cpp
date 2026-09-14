#include <cstdio>

int main()
{
    for (char c = 'a'; c != 'z'; c++)
        std::putc(c, stdout);

    // putchar's return value is not equal to the argument
    int r = 0x102A;
    std::printf("\nr = 0x%x\n", r);

    r = std::putchar(r);
    std::printf("\nr = 0x%x\n", r);
}