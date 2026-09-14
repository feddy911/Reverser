#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <initializer_list>

int main()
{
    std::setlocale(LC_ALL, "en_US.utf8");

    for (const wchar_t ch :
    {
        L'\u2200', // Unicode name: "FOR ALL"
            L'\n',
            L'∀',
    })
    {
        if (errno = 0; std::fputwc(ch, stdout) == WEOF)
        {
            std::puts(errno == EILSEQ
                ? "Encoding error in fputwc"
                : "I/O error in fputwc"
            );
            return EXIT_FAILURE;
        }
    }
        return EXIT_SUCCESS;
}