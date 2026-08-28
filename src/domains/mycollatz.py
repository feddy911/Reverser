from __future__ import annotations

from src.domains.pack import DomainPack

# Domain pack для эталонного samples/MyCollatz (MSVC x64 Debug + GMP).
# Не подключать по умолчанию для произвольных бинарников.
MYCOLLATZ = DomainPack(
    name="mycollatz",
    extra_includes=("#include <gmp.h>",),
    renames={
        "mpz_t": "mpz_view",
        "MyStruct": "CollatzState",
    },
    offset_map=(
        "+0x00 -> mpz_t number; +0x10 -> unsigned long long steps; "
        "+0x18 -> std::chrono::time_point startTime; +0x20 -> time_point endTime; "
        "+0x28 -> std::vector<std::string> history; +0x48 -> bool saveHistory; "
        "+0x49 -> bool verbose; +0x50 -> mpz_t milestone"
    ),
    idiom_map=(
        "(*(int*)(p+4)!=0)&**(uint**)(p+8) -> mpz_odd_p(number); "
        "CONCAT71(x,1) -> true/(bool); thunk_FUN_140021680 -> printf; "
        "thunk_FUN_14001e1b0 -> std::chrono::high_resolution_clock::now(); "
        "thunk_FUN_140014360/thunk_FUN_1400142e0 -> operator<< (cout/cerr); "
        "thunk_FUN_1400170b0 -> std::flush; thunk_FUN_140019050 -> ~std::string(); "
        "thunk_FUN_14001f100 -> history.push_back(...); "
        "thunk_FUN_14001d470 -> history.empty(); thunk_FUN_14001fb30 -> history.size()"
    ),
)
