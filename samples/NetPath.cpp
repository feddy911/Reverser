// samples/NetPath.cpp
// Undirected weighted graph; cheapest path by scanning (no priority_queue).
#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

static const int kInf = 1000000000;

using Graph = std::unordered_map<std::string, std::vector<std::pair<std::string, int>>>;

static void link_cities(Graph& g, const std::string& a, const std::string& b, int w) {
    g[a].push_back(std::make_pair(b, w));
    g[b].push_back(std::make_pair(a, w));
}

static void collect_nodes(const Graph& g, std::vector<std::string>& nodes) {
    nodes.clear();
    for (Graph::const_iterator it = g.begin(); it != g.end(); ++it) {
        nodes.push_back(it->first);
    }
}

static int cheapest_path(
    const Graph& g,
    const std::string& src,
    const std::string& dst,
    std::vector<std::string>& path
) {
    std::vector<std::string> nodes;
    collect_nodes(g, nodes);
    std::unordered_map<std::string, int> dist;
    std::unordered_map<std::string, std::string> prev;
    for (size_t i = 0; i < nodes.size(); ++i) {
        dist[nodes[i]] = kInf;
    }
    dist[src] = 0;

    std::vector<char> used(nodes.size(), 0);
    for (size_t step = 0; step < nodes.size(); ++step) {
        int best = -1;
        for (size_t i = 0; i < nodes.size(); ++i) {
            if (used[i]) {
                continue;
            }
            if (best < 0 || dist[nodes[i]] < dist[nodes[best]]) {
                best = static_cast<int>(i);
            }
        }
        if (best < 0 || dist[nodes[best]] >= kInf) {
            break;
        }
        used[static_cast<size_t>(best)] = 1;
        const std::string& u = nodes[static_cast<size_t>(best)];
        Graph::const_iterator git = g.find(u);
        if (git == g.end()) {
            continue;
        }
        const std::vector<std::pair<std::string, int>>& edges = git->second;
        for (size_t j = 0; j < edges.size(); ++j) {
            const std::string& v = edges[j].first;
            const int w = edges[j].second;
            const int cand = dist[u] + w;
            if (cand < dist[v]) {
                dist[v] = cand;
                prev[v] = u;
            }
        }
    }

    path.clear();
    if (dist.find(dst) == dist.end() || dist[dst] >= kInf) {
        return -1;
    }
    std::string cur = dst;
    while (true) {
        path.push_back(cur);
        if (cur == src) {
            break;
        }
        std::unordered_map<std::string, std::string>::const_iterator pit = prev.find(cur);
        if (pit == prev.end()) {
            path.clear();
            return -1;
        }
        cur = pit->second;
    }
    std::reverse(path.begin(), path.end());
    return dist[dst];
}

static void print_route(const std::vector<std::string>& path, int cost) {
    std::cout << "=== NetPath ===\n";
    std::cout << "cost=" << cost << "\n";
    std::cout << "route:";
    for (size_t i = 0; i < path.size(); ++i) {
        std::cout << " " << path[i];
    }
    std::cout << "\n";
}

int main() {
    Graph g;
    link_cities(g, "aa", "bb", 4);
    link_cities(g, "aa", "cc", 2);
    link_cities(g, "cc", "dd", 1);
    link_cities(g, "bb", "dd", 5);
    link_cities(g, "cc", "bb", 1);

    std::vector<std::string> path;
    const int cost = cheapest_path(g, "aa", "dd", path);
    print_route(path, cost);
    if (cost != 3 || path.size() != 3) {
        std::cout << "ERROR: expected aa-cc-dd cost 3\n";
        return 1;
    }
    std::cout << "ok\n";
    return 0;
}
