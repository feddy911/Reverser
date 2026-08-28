// samples/EchoFilter.cpp
// Filter stdin/argv lines by prefix; exercises strings + iostream.
#include <iostream>
#include <string>
#include <vector>

static bool starts_with(const std::string& s, const std::string& prefix) {
    if (prefix.size() > s.size()) {
        return false;
    }
    return s.compare(0, prefix.size(), prefix) == 0;
}

static void collect_matches(
    const std::vector<std::string>& lines,
    const std::string& prefix,
    std::vector<std::string>& out
) {
    for (const auto& line : lines) {
        if (starts_with(line, prefix)) {
            out.push_back(line);
        }
    }
}

static void print_report(const std::vector<std::string>& matched, const std::string& prefix) {
    std::cout << "=== EchoFilter report ===\n";
    std::cout << "Prefix: " << prefix << "\n";
    std::cout << "Matches: " << matched.size() << "\n";
    for (const auto& m : matched) {
        std::cout << "  > " << m << "\n";
    }
    if (matched.empty()) {
        std::cout << "(no matches)\n";
    }
}

int main(int argc, char** argv) {
    std::string prefix = "TODO:";
    std::vector<std::string> lines;

    if (argc >= 2) {
        prefix = argv[1];
    }
    for (int i = 2; i < argc; ++i) {
        lines.emplace_back(argv[i]);
    }
    if (lines.empty()) {
        lines = {
            "TODO: wire triage",
            "DONE: domain packs",
            "TODO: compile verify",
            "NOTE: sample binary",
        };
    }

    std::vector<std::string> matched;
    collect_matches(lines, prefix, matched);
    print_report(matched, prefix);
    return matched.empty() ? 1 : 0;
}
