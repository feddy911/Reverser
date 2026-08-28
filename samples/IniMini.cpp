// samples/IniMini.cpp
// Tiny key=value parser over embedded text; exercises strings + branching.
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

static std::string trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.pop_back();
    }
    return s;
}

static bool parse_line(const std::string& line, std::string& key, std::string& value) {
    if (line.empty() || line[0] == '#' || line[0] == ';') {
        return false;
    }
    const auto pos = line.find('=');
    if (pos == std::string::npos) {
        return false;
    }
    key = trim(line.substr(0, pos));
    value = trim(line.substr(pos + 1));
    return !key.empty();
}

static std::unordered_map<std::string, std::string> parse_ini(const std::vector<std::string>& lines) {
    std::unordered_map<std::string, std::string> kv;
    for (const auto& line : lines) {
        std::string key;
        std::string value;
        if (parse_line(line, key, value)) {
            kv[key] = value;
        }
    }
    return kv;
}

static void dump_map(const std::unordered_map<std::string, std::string>& kv) {
    std::cout << "=== IniMini dump ===\n";
    std::cout << "Entries: " << kv.size() << "\n";
    for (const auto& [k, v] : kv) {
        std::cout << k << " => " << v << "\n";
    }
}

int main() {
    const std::vector<std::string> sample = {
        "# demo config",
        "name = reverser",
        "mode=debug",
        "; ignore me",
        "threads = 4",
        "badline",
        "path = C:/tmp/out",
    };

    auto kv = parse_ini(sample);
    dump_map(kv);

    const auto it = kv.find("mode");
    if (it == kv.end()) {
        std::cout << "ERROR: mode missing\n";
        return 1;
    }
    std::cout << "Selected mode: " << it->second << "\n";
    return 0;
}
