#include <cstdio>

int main(void)
{
    int rc = std::fputs("Hello World", stdout);

    if (rc == EOF)
        std::perror("fputs()"); // POSIX requires that errno is set
}