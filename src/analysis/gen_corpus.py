from __future__ import annotations

"""Mini-program generator for the Ghidra-dialect corpus.

Fill path: tiny C++ → compile → (optional) Ghidra dump → draft YAML.
Drafts are NOT auto-accepted into eval/corpus/.

Identifier variation proves recipes are not glued to prefixPtr / EchoFilter names.

  py -m src.analysis.gen_corpus --out output/corpus_gen
  py -m src.analysis.gen_corpus --vary
  py -m src.analysis.gen_corpus --ghidra --config config.yaml
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from src.analysis.corpus import CorpusCase, apply_recipe, load_corpus
from src.analysis.ghidra_cpp import _KNOWN_CLASSES, _KNOWN_MEMBERS, _UNDERSCORE_TYPE_BASE

_IDENT = re.compile(r"(?<!::)\b([A-Za-z_]\w*)\b")

_CXX_KEYWORDS = frozenset({
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "register", "reinterpret_cast", "requires", "return",
    "short", "signed", "sizeof", "static", "static_assert", "static_cast",
    "struct", "switch", "template", "this", "thread_local", "throw", "true",
    "try", "typedef", "typeid", "typename", "union", "unsigned", "using",
    "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "size_t", "uintptr_t", "ptrdiff_t",
})

_PROTECTED_EXTRA = frozenset({
    "std", "chrono", "microseconds", "milliseconds", "duration_cast",
    "cout", "cerr", "endl", "cin", "string", "wstring", "vector",
    "basic_ostream", "char_traits", "allocator", "basic_string",
    "mpz_t", "mpz_ptr", "mpz_srcptr", "mpf_t", "mpq_t",
    "ghidra_word", "undefined", "undefined1", "undefined2", "undefined4",
    "undefined8", "longlong", "ulonglong", "size_type", "unsigned_char",
    "include",     "printf", "sprintf", "fprintf", "puts", "main",
    "initializer_list", "cmath", "cstdio", "cstring", "cstdint", "cstdlib",
    "algorithm", "iostream", "fstream", "chrono", "vector", "map", "set",
    "utility",
    "ofstream", "ifstream", "optional", "sort", "min", "max", "deque",
    "unordered_map", "unordered_set", "pair", "substr", "list", "empty",
    "compare", "append", "clear", "reverse", "emplace", "fill", "erase",
    "resize", "fabs", "multiset", "memcpy", "memcmp", "memset", "strlen",
    "swap", "length", "pop_back", "c_str", "strcmp", "strcpy", "memmove",
    "capacity", "printf", "puts", "strncpy", "sprintf", "atoi",
    "reserve", "second", "strcat", "snprintf", "log", "exp", "round",
    "conststd",
    "const_std",
    "_false",
    "_true",
    "_const",
    "__const_iterator",
    "const_iterator",
    "iterator",
    "time_point",
    "steady_clock",
    "system_clock",
    "const_reference",
    "__normal_iterator",
    "_Rb_tree_const_iterator",
    "__iterator",
    "ghidra_ref",
    "pointer",

    "ofstream", "ifstream", "optional", "sort", "min", "max",
    "sqrt", "pow", "fabs", "hypot", "sin", "cos", "tan",
    "log", "exp", "floor", "ceil", "round", "fmod", "atan2", "asin", "acos",
    "ios", "ios_base",
    "duration", "ratio", "rep",
    "nanoseconds", "microseconds", "milliseconds",
})


def _is_protected(ident: str) -> bool:
    if ident in _CXX_KEYWORDS or ident in _PROTECTED_EXTRA:
        return True
    if ident in _KNOWN_CLASSES or ident in _KNOWN_MEMBERS:
        return True
    if ident in {old for old, _new in _UNDERSCORE_TYPE_BASE}:
        return True
    if ident.startswith("_") and ident[1:] in {old for old, _new in _UNDERSCORE_TYPE_BASE}:
        return True
    # Ghidra dialect tokens (_std::, _DAT_, __gmpz_, …) must stay for recipes.
    if ident.startswith("_"):
        return True
    if ident.startswith((
        "DAT_", "thunk_", "FUN_", "std", "local_", "param_",
        "in_stack", "auStack", "mpz_", "long_long",
    )):
        return True
    return False


def _dialect_type_stems(idents: Sequence[str]) -> set[str]:
    """Stems of Ghidra const-T spellings (const_Rec / Rec_const). Do not vary them."""
    stems: set[str] = set()
    for ident in idents:
        if ident.startswith("_const_") and len(ident) > 7:
            stems.add(ident[7:])
        elif ident.startswith("const_") and ident != "const_iterator" and len(ident) > 6:
            stems.add(ident[6:])
        elif ident.endswith("_const") and len(ident) > 6:
            stems.add(ident[:-6])
    return stems


def ident_mapping(texts: Sequence[str], *, prefix: str = "v") -> Dict[str, str]:
    seen: List[str] = []
    all_idents: List[str] = []
    for text in texts:
        for ident in _IDENT.findall(text or ""):
            if ident not in all_idents:
                all_idents.append(ident)
    stems = _dialect_type_stems(all_idents)
    for ident in all_idents:
        if _is_protected(ident) or ident in seen or ident in stems:
            continue
        if ident.startswith("const_") or ident.endswith("_const"):
            continue
        seen.append(ident)
    return {name: f"{prefix}{i}" for i, name in enumerate(seen)}
    seen: List[str] = []
    for text in texts:
        for ident in _IDENT.findall(text or ""):
            if _is_protected(ident) or ident in seen:
                continue
            seen.append(ident)
    return {name: f"{prefix}{i}" for i, name in enumerate(seen)}


def apply_ident_map(text: str, mapping: Dict[str, str]) -> str:
    if not mapping:
        return text or ""

    def repl(m: re.Match) -> str:
        return mapping.get(m.group(1), m.group(1))

    return _IDENT.sub(repl, text or "")


def vary_case(case: CorpusCase, *, prefix: str = "v") -> Tuple[CorpusCase, Dict[str, str]]:
    extras_cpp = [e.get("cpp") or "" for e in case.extra_functions]
    mapping = ident_mapping(
        [case.ghidra_cpp, *extras_cpp, *case.contains, *case.not_contains],
        prefix=prefix,
    )
    extras = [
        {
            "name": apply_ident_map(e.get("name") or "", mapping),
            "cpp": apply_ident_map(e.get("cpp") or "", mapping),
        }
        for e in case.extra_functions
    ]
    varied = CorpusCase(
        id=case.id + "__vary",
        profile=case.profile,
        recipe=case.recipe,
        ghidra_cpp=apply_ident_map(case.ghidra_cpp, mapping),
        path=case.path,
        gcc_fingerprint=case.gcc_fingerprint,
        contains=[apply_ident_map(x, mapping) for x in case.contains],
        not_contains=[apply_ident_map(x, mapping) for x in case.not_contains],
        compile=False,
        requires=list(case.requires),
        guessed_name=apply_ident_map(case.guessed_name, mapping) or "f",
        extra_functions=extras,
        notes="identifier variation of " + case.id,
    )
    return varied, mapping


def eval_variations(
    cases: Optional[Sequence[CorpusCase]] = None,
) -> Dict[str, object]:
    loaded = list(cases) if cases is not None else load_corpus()
    results = []
    for case in loaded:
        varied, mapping = vary_case(case)
        try:
            got = apply_recipe(varied)
        except Exception as exc:
            results.append({
                "id": case.id, "ok": False, "error": str(exc), "n_map": len(mapping),
            })
            continue
        errors = []
        for needle in varied.contains:
            if needle not in got:
                errors.append(f"missing contains: {needle!r}")
        for needle in varied.not_contains:
            if needle in got:
                errors.append(f"hit not_contains: {needle!r}")
        results.append({
            "id": case.id,
            "ok": not errors,
            "errors": errors,
            "n_map": len(mapping),
        })
    n_ok = sum(1 for r in results if r.get("ok"))
    return {"n_cases": len(results), "n_ok": n_ok, "n_fail": len(results) - n_ok, "results": results}


@dataclass
class MiniProgram:
    id: str
    source: str
    dialect: str
    requires: List[str] = field(default_factory=list)


MINI_PROGRAMS: Tuple[MiniProgram, ...] = (
    MiniProgram(
        id="iostream_shift",
        dialect="iostream",
        source="""#include <iostream>
#include <cstdint>
int report_n(std::uint64_t n) {
  std::cout << "n=" << n << "\\n";
  return 0;
}
int main() { return report_n(1); }
""",
    ),
    MiniProgram(
        id="string_assign",
        dialect="string",
        source="""#include <string>
std::string prefix_of(const std::string &src, const std::string &pfx) {
  std::string out;
  out = pfx;
  out += src;
  return out;
}
int main() { return prefix_of("abc", "x").size() == 4 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="vector_reserve",
        dialect="vector",
        source="""#include <vector>
#include <cstdint>
void fill_n(std::vector<std::uint64_t> *p, int n) {
  p->reserve(static_cast<std::size_t>(n));
  p->push_back(1);
}
int main() { std::vector<std::uint64_t> v; fill_n(&v, 4); return (int)v.size() - 1; }
""",
    ),
    MiniProgram(
        id="chrono_cast",
        dialect="chrono",
        source="""#include <chrono>
long long to_us(std::chrono::steady_clock::duration d) {
  return std::chrono::duration_cast<std::chrono::microseconds>(d).count();
}
int main() { return to_us(std::chrono::microseconds{1}) == 1 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="chrono_now",
        dialect="chrono",
        source="""#include <chrono>
long long elapsed_us() {
  auto t0 = std::chrono::steady_clock::now();
  auto t1 = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
}
int main() { return elapsed_us() >= 0 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="mingw_main",
        dialect="crt",
        source="""int helper() { return 0; }
int main() { return helper(); }
""",
    ),
    MiniProgram(
        id="gmp_init",
        dialect="gmp",
        requires=["gmp"],
        source="""#include <gmp.h>
void init_one(mpz_t x) {
  mpz_init(x);
  mpz_set_ui(x, 1);
}
int main() { mpz_t x; init_one(x); mpz_clear(x); return 0; }
""",
    ),
    MiniProgram(
        id="hypot_sqrt",
        dialect="cmath",
        source="""#include <cmath>
double mag(double x, double y) {
  return std::sqrt(x * x + y * y);
}
int main() { return mag(3.0, 4.0) > 4.0 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="init_list_vector",
        dialect="initializer_list",
        source="""#include <vector>
#include <cstdint>
int sum3() {
  std::vector<std::uint64_t> xs{1, 2, 3};
  return (int)(xs[0] + xs[1] + xs[2]);
}
int main() { return sum3() == 6 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="string_find",
        dialect="string",
        source="""#include <string>
int has_pre(const std::string &src, const std::string &pre) {
  return src.find(pre) == 0 ? 1 : 0;
}
int main() { return has_pre("abc", "a") ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="map_count",
        dialect="map",
        source="""#include <map>
#include <cstdint>
int has_key(std::map<int, std::uint64_t> *m, int k) {
  return m->count(k) ? 1 : 0;
}
int main() {
  std::map<int, std::uint64_t> m;
  m[1] = 2;
  return has_key(&m, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="fstream_write",
        dialect="fstream",
        source="""#include <fstream>
int write_n(const char *path, int n) {
  std::ofstream out(path);
  out << n;
  return out.good() ? 0 : 1;
}
int main() { return write_n("nul", 1); }
""",
    ),
    MiniProgram(
        id="set_count",
        dialect="set",
        source="""#include <set>
int has_n(std::set<int> *s, int n) {
  return s->count(n) ? 1 : 0;
}
int main() {
  std::set<int> s;
  s.insert(1);
  return has_n(&s, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="optional_value",
        dialect="optional",
        source="""#include <optional>
int or_zero(std::optional<int> *p) {
  return p->value_or(0);
}
int main() {
  std::optional<int> x{3};
  return or_zero(&x) == 3 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="algo_sort",
        dialect="algorithm",
        source="""#include <algorithm>
void order2(int *p) {
  std::sort(p, p + 2);
}
int main() {
  int xs[2] = {2, 1};
  order2(xs);
  return xs[0] == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="umap_count",
        dialect="unordered_map",
        source="""#include <unordered_map>
int has_key(std::unordered_map<int, int> *m, int k) {
  return m->count(k) ? 1 : 0;
}
int main() {
  std::unordered_map<int, int> m;
  m.emplace(1, 2);
  return has_key(&m, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="umap_collect",
        dialect="unordered_map",
        source="""#include <unordered_map>
std::unordered_map<int, int> * collect(std::unordered_map<int, int> *m) {
  return m;
}
int main() {
  std::unordered_map<int, int> m;
  m.emplace(1, 2);
  return collect(&m)->size() == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="umap_show_val",
        dialect="unordered_map",
        source="""#include <iostream>
#include <string>
#include <unordered_map>
void show_val(std::unordered_map<std::string, std::string> *m) {
  auto it = m->find("a");
  if (it != m->end()) {
    std::cout << it->second;
  }
}
int main() {
  std::unordered_map<std::string, std::string> m;
  m.emplace("a", "x");
  show_val(&m);
  return 0;
}
""",
    ),
    MiniProgram(
        id="umap_str_walk",
        dialect="unordered_map",
        source="""#include <string>
#include <unordered_map>
int sum_vals(std::unordered_map<std::string, std::string> *m) {
  int n = 0;
  for (const auto& kv : *m) {
    n += (int)kv.second.size();
  }
  return n;
}
int has_a(std::unordered_map<std::string, std::string> *m) {
  const auto it = m->find("a");
  if (it == m->end()) {
    return 0;
  }
  return it->second.size() ? 1 : 0;
}
int main() {
  std::unordered_map<std::string, std::string> m;
  m.emplace("a", "bb");
  return (sum_vals(&m) == 2 && has_a(&m)) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_substr",
        dialect="string",
        source="""#include <string>
int take2(const std::string &s) {
  return (int)s.substr(0, 2).size();
}
int main() { return take2("ab") == 2 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="pair_first",
        dialect="pair",
        source="""#include <utility>
int first_of(std::pair<int, int> *p) {
  return p->first;
}
int main() {
  std::pair<int, int> x{3, 4};
  return first_of(&x) == 3 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="deque_push",
        dialect="deque",
        source="""#include <deque>
void add_front(std::deque<int> *d) {
  d->push_front(1);
}
int main() {
  std::deque<int> d;
  add_front(&d);
  return d.front() == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_empty",
        dialect="vector",
        source="""#include <vector>
int is_empty(std::vector<int> *v) {
  return v->empty() ? 1 : 0;
}
int main() {
  std::vector<int> v;
  return is_empty(&v) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_compare",
        dialect="string",
        source="""#include <string>
int same_as(std::string *a, std::string *b) {
  return a->compare(*b) == 0 ? 1 : 0;
}
int main() {
  std::string a("ab");
  std::string b("ab");
  return same_as(&a, &b) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="list_size",
        dialect="list",
        source="""#include <list>
int len(std::list<int> *l) {
  return (int)l->size();
}
int main() {
  std::list<int> l;
  l.push_back(1);
  return len(&l) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="map_emplace",
        dialect="map",
        source="""#include <map>
int has_key(std::map<int, int> *m, int k) {
  return m->count(k) ? 1 : 0;
}
int main() {
  std::map<int, int> m;
  m.emplace(1, 2);
  return has_key(&m, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="uset_count",
        dialect="unordered_set",
        source="""#include <unordered_set>
int has_n(std::unordered_set<int> *s, int n) {
  return s->count(n) ? 1 : 0;
}
int main() {
  std::unordered_set<int> s;
  s.insert(1);
  return has_n(&s, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="algo_reverse",
        dialect="algorithm",
        source="""#include <algorithm>
void flip2(int *p) {
  std::reverse(p, p + 2);
}
int main() {
  int xs[2] = {1, 2};
  flip2(xs);
  return xs[0] == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_append",
        dialect="string",
        source="""#include <string>
void add_on(std::string *s, std::string *t) {
  s->append(*t);
}
int main() {
  std::string a("a");
  std::string b("b");
  add_on(&a, &b);
  return a.size() == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_clear",
        dialect="vector",
        source="""#include <vector>
void wipe(std::vector<int> *v) {
  v->clear();
}
int main() {
  std::vector<int> v;
  v.push_back(1);
  wipe(&v);
  return v.empty() ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="algo_fill",
        dialect="algorithm",
        source="""#include <algorithm>
void ones2(int *p) {
  std::fill(p, p + 2, 1);
}
int main() {
  int xs[2] = {0, 0};
  ones2(xs);
  return xs[0] == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_erase",
        dialect="string",
        source="""#include <string>
void drop_first(std::string *s) {
  s->erase(0, 1);
}
int main() {
  std::string a("ab");
  drop_first(&a);
  return a.size() == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_trim_ws",
        dialect="string",
        source="""#include <string>
void ltrim_space(std::string *s) {
  while (!s->empty() && s->front() == ' ') {
    s->erase(s->begin());
  }
}
void rtrim_space(std::string *s) {
  while (!s->empty() && s->back() == ' ') {
    s->pop_back();
  }
}
int main() {
  std::string a(" x ");
  ltrim_space(&a);
  rtrim_space(&a);
  return a == "x" ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_ret_ws",
        dialect="string",
        source="""#include <string>
std::string trim_copy(std::string s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\\t')) {
    s.erase(s.begin());
  }
  while (!s.empty() && s.back() == ' ') {
    s.pop_back();
  }
  return s;
}
int main() {
  return trim_copy(" x") == "x" ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_at0",
        dialect="string",
        source="""#include <string>
int is_hash(const std::string *s) {
  return (!s->empty() && (*s)[0] == '#') ? 1 : 0;
}
int main() {
  std::string a("#x");
  return is_hash(&a) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vec_sum_n",
        dialect="vector",
        source="""#include <vector>
int sum_n(const std::vector<int> *v) {
  int n = 0;
  for (int x : *v) {
    n += x;
  }
  return n;
}
int main() {
  std::vector<int> v;
  v.push_back(1);
  v.push_back(2);
  return sum_n(&v) == 3 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="map_walk_n",
        dialect="map",
        source="""#include <map>
int sum_keys(const std::map<int, int> *m) {
  int n = 0;
  for (std::map<int, int>::const_iterator it = m->begin(); it != m->end(); ++it) {
    n += it->first;
  }
  return n;
}
int main() {
  std::map<int, int> m;
  m[1] = 0;
  m[2] = 0;
  return sum_keys(&m) == 3 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vec_field_n",
        dialect="vector",
        source="""#include <vector>
struct Rec {
  int n;
};
int first_n(const std::vector<Rec> *v) {
  return v->empty() ? 0 : (*v)[0].n;
}
int main() {
  std::vector<Rec> v;
  Rec r;
  r.n = 4;
  v.push_back(r);
  return first_n(&v) == 4 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vec_sort_n",
        dialect="algorithm",
        source="""#include <algorithm>
#include <vector>
struct Rec {
  int n;
};
void order_n(std::vector<Rec> *v) {
  std::sort(v->begin(), v->end(), [](Rec a, Rec b) { return a.n < b.n; });
}
int main() {
  std::vector<Rec> v;
  Rec r;
  r.n = 2;
  v.push_back(r);
  r.n = 1;
  v.push_back(r);
  order_n(&v);
  return v[0].n == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vec_range_for",
        dialect="vector",
        source="""#include <string>
#include <vector>
bool has_pref(std::string const *s, std::string const *p) {
  return s->size() >= p->size() && s->compare(0, p->size(), *p) == 0;
}
int count_pref(std::vector<std::string> const *lines, std::string const *prefix) {
  int n = 0;
  for (std::string const &line : *lines) {
    if (has_pref(&line, prefix)) n++;
  }
  return n;
}
int main() {
  std::vector<std::string> v{"ab", "cd"};
  std::string p{"a"};
  return count_pref(&v, &p) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vec_fill_n",
        dialect="vector",
        source="""#include <vector>
void fill_n(std::vector<char> *v, int n) {
  *v = std::vector<char>((std::size_t)n, 'a');
}
int main() {
  std::vector<char> v;
  fill_n(&v, 3);
  return (int)v.size() == 3 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_resize",
        dialect="vector",
        source="""#include <vector>
void to_n(std::vector<int> *v, int n) {
  v->resize((std::size_t)n);
}
int main() {
  std::vector<int> v;
  to_n(&v, 2);
  return (int)v.size() == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cmath_fabs",
        dialect="cmath",
        source="""#include <cmath>
double abs1(double x) {
  return std::fabs(x);
}
int main() { return abs1(-1.0) > 0.5 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="mset_count",
        dialect="multiset",
        source="""#include <set>
int has_n(std::multiset<int> *s, int n) {
  return s->count(n) ? 1 : 0;
}
int main() {
  std::multiset<int> s;
  s.insert(1);
  return has_n(&s, 1) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstring_memcpy",
        dialect="cstring",
        source="""#include <cstring>
void copy2(char *d, const char *s) {
  memcpy(d, s, 2);
}
int main() {
  char a[3] = {0, 0, 0};
  copy2(a, "ab");
  return a[0] == 'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstring_memcmp",
        dialect="cstring",
        source="""#include <cstring>
int same2(const char *a, const char *b) {
  return memcmp(a, b, 2) == 0 ? 1 : 0;
}
int main() { return same2("ab", "ab") ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="utility_swap",
        dialect="utility",
        source="""#include <utility>
void swap2(int *a, int *b) {
  std::swap(*a, *b);
}
int main() {
  int x = 1, y = 2;
  swap2(&x, &y);
  return x == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_length",
        dialect="string",
        source="""#include <string>
int len_of(std::string *s) {
  return (int)s->length();
}
int main() {
  std::string a("ab");
  return len_of(&a) == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_pop_back",
        dialect="vector",
        source="""#include <vector>
void drop_last(std::vector<int> *v) {
  v->pop_back();
}
int main() {
  std::vector<int> v;
  v.push_back(1);
  v.push_back(2);
  drop_last(&v);
  return (int)v.size() == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstring_strlen",
        dialect="cstring",
        source="""#include <cstring>
int len2(const char *s) {
  return (int)strlen(s);
}
int main() { return len2("ab") == 2 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstring_memset",
        dialect="cstring",
        source="""#include <cstring>
void zero2(char *p) {
  memset(p, 0, 2);
}
int main() {
  char a[2] = {1, 1};
  zero2(a);
  return a[0] == 0 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_c_str",
        dialect="string",
        source="""#include <string>
int first_ch(std::string *s) {
  return (int)(unsigned char)s->c_str()[0];
}
int main() {
  std::string a("ab");
  return first_ch(&a) == (int)'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_size",
        dialect="vector",
        source="""#include <vector>
int len_of(std::vector<int> *v) {
  return (int)v->size();
}
int main() {
  std::vector<int> v;
  v.push_back(1);
  return len_of(&v) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cmath_pow",
        dialect="cmath",
        source="""#include <cmath>
double cube(double x) {
  return std::pow(x, 3.0);
}
int main() { return cube(2.0) > 7.0 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstring_strcmp",
        dialect="cstring",
        source="""#include <cstring>
int same_ab(const char *s) {
  return strcmp(s, "ab") == 0 ? 1 : 0;
}
int main() { return same_ab("ab") ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstring_memmove",
        dialect="cstring",
        source="""#include <cstring>
void shift1(char *p) {
  memmove(p + 1, p, 2);
}
int main() {
  char a[4] = {'a', 'b', 'c', 0};
  shift1(a);
  return a[1] == 'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstring_strcpy",
        dialect="cstring",
        source="""#include <cstring>
void copy_ab(char *d) {
  strcpy(d, "ab");
}
int main() {
  char a[4] = {0};
  copy_ab(a);
  return a[0] == 'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_clear",
        dialect="string",
        source="""#include <string>
void wipe_s(std::string *s) {
  s->clear();
}
int main() {
  std::string a("ab");
  wipe_s(&a);
  return a.empty() ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_data",
        dialect="string",
        source="""#include <string>
int byte0(std::string *s) {
  return (int)(unsigned char)s->data()[0];
}
int main() {
  std::string a("ab");
  return byte0(&a) == (int)'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_empty",
        dialect="string",
        source="""#include <string>
int no_chars(std::string *s) {
  return s->empty() ? 1 : 0;
}
int main() {
  std::string a;
  return no_chars(&a) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="vector_capacity",
        dialect="vector",
        source="""#include <vector>
int cap_of(std::vector<int> *v) {
  return (int)v->capacity();
}
int main() {
  std::vector<int> v;
  v.reserve(4);
  return cap_of(&v) >= 4 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cmath_floor",
        dialect="cmath",
        source="""#include <cmath>
int trunc1(double x) {
  return (int)std::floor(x);
}
int main() { return trunc1(1.9) == 1 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cmath_sin",
        dialect="cmath",
        source="""#include <cmath>
double sin0(double x) {
  return std::sin(x);
}
int main() { return sin0(0.0) > -0.1 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstdio_printf",
        dialect="cstdio",
        source="""#include <cstdio>
int say_n(int n) {
  printf("%d\\n", n);
  return 0;
}
int main() { return say_n(1); }
""",
    ),
    MiniProgram(
        id="cmath_ceil",
        dialect="cmath",
        source="""#include <cmath>
int ceil_up(double x) {
  return (int)std::ceil(x);
}
int main() { return ceil_up(1.1) == 2 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cmath_cos",
        dialect="cmath",
        source="""#include <cmath>
double cos0(double x) {
  return std::cos(x);
}
int main() { return cos0(0.0) > 0.5 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstring_strncpy",
        dialect="cstring",
        source="""#include <cstring>
void copy3(char *d, const char *s) {
  strncpy(d, s, 3);
}
int main() {
  char a[4] = {0};
  copy3(a, "abc");
  return a[0] == 'a' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstdio_sprintf",
        dialect="cstdio",
        source="""#include <cstdio>
int fmt_n(char *buf, int n) {
  return sprintf(buf, "%d", n);
}
int main() {
  char b[16];
  return fmt_n(b, 1) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstdlib_atoi",
        dialect="cstdlib",
        source="""#include <cstdlib>
int parse1(const char *s) {
  return atoi(s);
}
int main() { return parse1("1") == 1 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="string_resize",
        dialect="string",
        source="""#include <string>
void to_len(std::string *s, int n) {
  s->resize((std::size_t)n);
}
int main() {
  std::string a;
  to_len(&a, 2);
  return a.size() == 2 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_reserve",
        dialect="string",
        source="""#include <string>
void room_n(std::string *s, int n) {
  s->reserve((std::size_t)n);
}
int main() {
  std::string a;
  room_n(&a, 8);
  return a.capacity() >= 8 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="pair_second",
        dialect="pair",
        source="""#include <utility>
int second_of(std::pair<int, int> *p) {
  return p->second;
}
int main() {
  std::pair<int, int> x{3, 4};
  return second_of(&x) == 4 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="list_empty",
        dialect="list",
        source="""#include <list>
int no_items(std::list<int> *l) {
  return l->empty() ? 1 : 0;
}
int main() {
  std::list<int> l;
  return no_items(&l) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="set_empty",
        dialect="set",
        source="""#include <set>
int no_vals(std::set<int> *s) {
  return s->empty() ? 1 : 0;
}
int main() {
  std::set<int> s;
  return no_vals(&s) ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cmath_log",
        dialect="cmath",
        source="""#include <cmath>
double ln1(double x) {
  return std::log(x);
}
int main() { return ln1(1.0) > -0.1 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cmath_exp",
        dialect="cmath",
        source="""#include <cmath>
double e1(double x) {
  return std::exp(x);
}
int main() { return e1(0.0) > 0.5 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cmath_round",
        dialect="cmath",
        source="""#include <cmath>
int near1(double x) {
  return (int)std::round(x);
}
int main() { return near1(1.6) == 2 ? 0 : 1; }
""",
    ),
    MiniProgram(
        id="cstring_strcat",
        dialect="cstring",
        source="""#include <cstring>
void cat_b(char *d) {
  strcat(d, "b");
}
int main() {
  char a[4] = {'a', 0, 0, 0};
  cat_b(a);
  return a[1] == 'b' ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="cstdio_puts",
        dialect="cstdio",
        source="""#include <cstdio>
int say_hi() {
  puts("hi");
  return 0;
}
int main() { return say_hi(); }
""",
    ),
    MiniProgram(
        id="cstdio_snprintf",
        dialect="cstdio",
        source="""#include <cstdio>
int fmt16(char *buf, int n) {
  return snprintf(buf, 16, "%d", n);
}
int main() {
  char b[16];
  return fmt16(b, 1) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="string_push_back",
        dialect="string",
        source="""#include <string>
void add_x(std::string *s) {
  s->push_back('x');
}
int main() {
  std::string a;
  add_x(&a);
  return a.size() == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="map_size",
        dialect="map",
        source="""#include <map>
int n_keys(std::map<int, int> *m) {
  return (int)m->size();
}
int main() {
  std::map<int, int> m;
  m.emplace(1, 2);
  return n_keys(&m) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="map_str_size",
        dialect="map",
        source="""#include <map>
#include <string>
int n_str_keys(std::map<std::string, std::string> *m) {
  return (int)m->size();
}
int main() {
  std::map<std::string, std::string> m;
  m.emplace("a", "b");
  return n_str_keys(&m) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="set_size",
        dialect="set",
        source="""#include <set>
int n_vals(std::set<int> *s) {
  return (int)s->size();
}
int main() {
  std::set<int> s;
  s.insert(1);
  return n_vals(&s) == 1 ? 0 : 1;
}
""",
    ),
    MiniProgram(
        id="list_clear",
        dialect="list",
        source="""#include <list>
void wipe_l(std::list<int> *l) {
  l->clear();
}
int main() {
  std::list<int> l;
  l.push_back(1);
  wipe_l(&l);
  return l.empty() ? 0 : 1;
}
""",
    ),
)


HELDOUT_PROGRAMS: Tuple[MiniProgram, ...] = (
    MiniProgram(
        id="heldout_struct_math",
        dialect="heldout",
        source="""#include <cstdio>
struct CloudPt { double x; double y; };
static double dist2(const CloudPt& a, const CloudPt& b) {
  const double dx = a.x - b.x;
  const double dy = a.y - b.y;
  return dx * dx + dy * dy;
}
static int closest_ix(CloudPt* pts, int n, const CloudPt& query) {
  int best = 0;
  double best_d = dist2(pts[0], query);
  for (int i = 1; i < n; ++i) {
    const double d = dist2(pts[i], query);
    if (d < best_d) { best_d = d; best = i; }
  }
  return best;
}
int main() {
  CloudPt cloud[2] = {{0.0, 0.0}, {3.0, 4.0}};
  CloudPt query{1.0, 1.0};
  std::printf("heldout\\n");
  return closest_ix(cloud, 2, query);
}
""",
    ),
)


def emit_programs(
    out_dir: Path,
    programs: Sequence[MiniProgram] = MINI_PROGRAMS,
) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for prog in programs:
        path = out_dir / f"{prog.id}.cpp"
        path.write_text(prog.source, encoding="utf-8")
        written.append(path)
    return written


def compile_programs(
    out_dir: Path,
    *,
    compiler: str = "",
    programs: Sequence[MiniProgram] = MINI_PROGRAMS,
) -> List[Dict[str, object]]:
    from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
    from src.analysis.corpus import _gmp_available

    cxx = find_cxx_compiler(compiler)
    reports = []
    for prog in programs:
        src = out_dir / f"{prog.id}.cpp"
        rec: Dict[str, object] = {"id": prog.id, "path": str(src), "ok": False}
        if not src.exists():
            rec["error"] = "missing source"
            reports.append(rec)
            continue
        if not cxx:
            rec["skipped"] = "no C++ compiler"
            reports.append(rec)
            continue
        if "gmp" in prog.requires and not _gmp_available(cxx):
            rec["skipped"] = "gmp.h not available"
            rec["ok"] = True
            reports.append(rec)
            continue
        crep = compile_cpp(src, compiler=cxx, timeout_sec=30)
        rec["ok"] = bool(crep.ok)
        rec["n_errors"] = crep.n_errors
        rec["skipped"] = crep.skipped_reason
        if not crep.ok:
            rec["stderr"] = (crep.stderr or "")[-500:]
        reports.append(rec)
    return reports


def _slug(text: str, n: int = 12) -> str:
    return hashlib.sha1((text or "").encode("utf-8")).hexdigest()[:n]


def drafts_from_ghidra(
    ghidra: Dict,
    *,
    program_id: str,
    out_dir: Path,
    profile: str = "generic",
) -> List[Path]:
    """Write unevaluated YAML drafts. Not loaded by eval_corpus (subdir)."""
    import yaml

    from src.analysis.platform import is_runtime_noise

    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for fn in ghidra.get("functions") or []:
        code = (fn.get("code") or fn.get("ghidra_code") or "").strip()
        size = int(fn.get("size") or 0)
        name = str(fn.get("name") or "f")
        if size < 8 or not code:
            continue
        if is_runtime_noise(name) or name.startswith("__"):
            continue
        cid = f"draft-{program_id}-{_slug(name + code)}"
        payload = {
            "id": cid,
            "profile": profile,
            "recipe": "sanitize",
            "ghidra_cpp": code,
            "contains": [],
            "not_contains": [],
            "compile": False,
            "guessed_name": name,
            "notes": (
                f"auto-draft from generator program {program_id}; "
                "not accepted into eval/corpus"
            ),
        }
        path = out_dir / f"{cid}.yaml"
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        written.append(path)
    return written


def run_ghidra_on_programs(
    out_dir: Path,
    *,
    ghidra_path: Path,
    draft_dir: Path,
    timeout_sec: int = 900,
    programs: Optional[Sequence[MiniProgram]] = None,
    dump_dir: Optional[Path] = None,
    force: bool = False,
) -> List[Dict[str, object]]:
    """Link mini-programs and decompile. Dumps are persisted under dump_dir."""
    import subprocess

    from src.analysis.compile_verify import find_cxx_compiler
    from src.ghidra.headless import run_ghidra_decompile

    cxx = find_cxx_compiler()
    if not cxx:
        return [{"error": "no C++ compiler for --ghidra"}]
    root = Path(__file__).resolve().parents[2]
    dump_dir = dump_dir or (out_dir / "ghidra_dumps")
    dump_dir.mkdir(parents=True, exist_ok=True)
    wanted = list(programs) if programs is not None else list(MINI_PROGRAMS) + list(
        HELDOUT_PROGRAMS
    )
    reports = []
    for prog in wanted:
        if prog.requires:
            continue
        src = out_dir / f"{prog.id}.cpp"
        if not src.exists():
            src = out_dir / "heldout" / f"{prog.id}.cpp"
        if not src.exists():
            continue
        dump = dump_dir / f"{prog.id}.json"
        rec: Dict[str, object] = {"id": prog.id, "dump": str(dump)}
        if dump.exists() and not force:
            rec["cached"] = True
            data = json.loads(dump.read_text(encoding="utf-8"))
            paths = drafts_from_ghidra(data, program_id=prog.id, out_dir=draft_dir)
            rec["drafts"] = [str(p) for p in paths]
            reports.append(rec)
            continue
        exe = dump_dir / f"{prog.id}.exe"
        link = subprocess.run(
            [cxx, "-std=c++17", "-O0", "-g", str(src), "-o", str(exe)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        rec["linked"] = link.returncode == 0
        if link.returncode != 0:
            rec["stderr"] = (link.stderr or "")[-500:]
            reports.append(rec)
            continue
        proj = dump_dir / f"{prog.id}_proj"
        try:
            ghidra = run_ghidra_decompile(
                ghidra_path,
                exe,
                proj,
                [root / "scripts", root / "src" / "ghidra"],
                dump,
                timeout_sec=timeout_sec,
            )
        except Exception as exc:
            rec["error"] = str(exc)
            reports.append(rec)
            continue
        paths = drafts_from_ghidra(ghidra, program_id=prog.id, out_dir=draft_dir)
        rec["drafts"] = [str(p) for p in paths]
        reports.append(rec)
    return reports


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate corpus mini-programs / variations")
    parser.add_argument("--out", default="output/corpus_gen", help="Where to write .cpp")
    parser.add_argument("--vary", action="store_true", help="Re-eval corpus with renamed idents")
    parser.add_argument("--compile", action="store_true", help="Syntax-check emitted programs")
    parser.add_argument("--ghidra", action="store_true", help="Link + Ghidra dump → draft YAML")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--draft-dir", default="output/corpus_draft")
    parser.add_argument("--force-ghidra", action="store_true", help="Re-decompile even if dump exists")
    parser.add_argument("--ids", action="append", help="Only these program ids (repeatable)")
    parser.add_argument("--no-emit", action="store_true")
    parser.add_argument(
        "--heldout",
        action="store_true",
        help="Emit/compile P2 held-out programs (not used to write recipes)",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    rc = 0
    if not args.no_emit:
        paths = emit_programs(out_dir)
        print(f"OK: emitted {len(paths)} programs -> {out_dir}")

    if args.compile or args.ghidra:
        reports = compile_programs(out_dir)
        n_ok = sum(1 for r in reports if r.get("ok") or r.get("skipped"))
        print(f"OK: compile {n_ok}/{len(reports)}")
        for r in reports:
            if not r.get("ok") and not r.get("skipped"):
                rc = 1
                print(f"  FAIL {r['id']}: {r.get('stderr') or r.get('error')}")
            else:
                print(f"  OK   {r['id']}" + (f" skip={r.get('skipped')}" if r.get("skipped") else ""))

    if args.vary:
        report = eval_variations()
        print(f"OK: vary {report['n_ok']}/{report['n_cases']}")
        for r in report["results"]:
            if r.get("ok"):
                print(f"  OK   {r['id']} map={r.get('n_map')}")
            else:
                rc = 1
                print(f"  FAIL {r['id']}: {r.get('errors') or r.get('error')}")

    if args.heldout:
        hdir = out_dir / "heldout"
        paths = emit_programs(hdir, programs=HELDOUT_PROGRAMS)
        print(f"OK: heldout emitted {len(paths)} -> {hdir}")
        if args.compile or args.ghidra:
            reports = compile_programs(hdir, programs=HELDOUT_PROGRAMS)
            n_ok = sum(1 for r in reports if r.get("ok") or r.get("skipped"))
            print(f"OK: heldout compile {n_ok}/{len(reports)}")
            for r in reports:
                if not r.get("ok") and not r.get("skipped"):
                    rc = 1
                    print(f"  FAIL {r['id']}: {r.get('stderr') or r.get('error')}")
                else:
                    print(f"  OK   {r['id']}")
            print("note: held-out compile of SOURCE is not a recipe; do not patch sanitizer")

    if args.ghidra:
        from src.config import load_config

        emit_programs(out_dir / "heldout", programs=HELDOUT_PROGRAMS)
        cfg = load_config(args.config)
        if not cfg.ghidra_path:
            print("FAIL: --ghidra needs ghidra_path in config")
            return 2
        wanted = None
        if args.ids:
            by_id = {p.id: p for p in list(MINI_PROGRAMS) + list(HELDOUT_PROGRAMS)}
            wanted = [by_id[i] for i in args.ids if i in by_id]
            if not wanted:
                print("FAIL: --ids matched no programs")
                return 2
        reports = run_ghidra_on_programs(
            out_dir,
            ghidra_path=Path(cfg.ghidra_path),
            draft_dir=Path(args.draft_dir),
            timeout_sec=cfg.ghidra_timeout,
            programs=wanted,
            dump_dir=out_dir / "ghidra_dumps",
            force=args.force_ghidra,
        )
        print(f"OK: ghidra drafts -> {args.draft_dir}")
        for r in reports:
            print(f"  {r.get('id', '?')}: {r}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
