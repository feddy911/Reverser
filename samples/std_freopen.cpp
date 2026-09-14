#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>

int main()
{
    std::printf("stdout is printed to console\n");
    if (std::freopen("redir.txt", "w", stdout))
    {
        std::printf("stdout is redirected to a file\n"); // this is written to redir.txt
        std::fclose(stdout);
    }
}