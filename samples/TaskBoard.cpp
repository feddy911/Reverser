// samples/TaskBoard.cpp
// Open tasks: filter, rank, group-by owner. Structs + vector + map + sort.
#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>

struct Item {
    std::string id;
    std::string owner;
    int prio;
    int done;
};

static Item make_item(const char* id, const char* owner, int prio, int done) {
    Item it;
    it.id = id;
    it.owner = owner;
    it.prio = prio;
    it.done = done;
    return it;
}

static std::vector<Item> load_board() {
    std::vector<Item> out;
    out.push_back(make_item("t1", "ann", 3, 0));
    out.push_back(make_item("t2", "bob", 1, 1));
    out.push_back(make_item("t3", "ann", 5, 0));
    out.push_back(make_item("t4", "cam", 2, 0));
    out.push_back(make_item("t5", "bob", 4, 0));
    return out;
}

static int is_open(const Item& it) {
    return it.done == 0;
}

static bool prio_then_id(const Item& a, const Item& b) {
    if (a.prio != b.prio) {
        return a.prio > b.prio;
    }
    return a.id < b.id;
}

static std::vector<Item> rank_open(const std::vector<Item>& items) {
    std::vector<Item> open;
    for (size_t i = 0; i < items.size(); ++i) {
        if (is_open(items[i])) {
            open.push_back(items[i]);
        }
    }
    std::sort(open.begin(), open.end(), prio_then_id);
    return open;
}

static std::map<std::string, int> tally_owners(const std::vector<Item>& items) {
    std::map<std::string, int> n;
    for (size_t i = 0; i < items.size(); ++i) {
        if (is_open(items[i])) {
            n[items[i].owner] += 1;
        }
    }
    return n;
}

static void print_ranked(const std::vector<Item>& open) {
    std::cout << "=== TaskBoard ===\n";
    std::cout << "open=" << open.size() << "\n";
    for (size_t i = 0; i < open.size(); ++i) {
        std::cout << open[i].id << " owner=" << open[i].owner
                  << " prio=" << open[i].prio << "\n";
    }
}

static void print_tally(const std::map<std::string, int>& n) {
    std::cout << "by_owner:\n";
    for (std::map<std::string, int>::const_iterator it = n.begin(); it != n.end(); ++it) {
        std::cout << it->first << " => " << it->second << "\n";
    }
}

int main() {
    const std::vector<Item> board = load_board();
    const std::vector<Item> open = rank_open(board);
    print_ranked(open);
    const std::map<std::string, int> n = tally_owners(board);
    print_tally(n);
    if (open.empty() || open[0].id != "t3") {
        std::cout << "ERROR: expected t3 first\n";
        return 1;
    }
    std::cout << "top=" << open[0].id << "\n";
    return 0;
}
