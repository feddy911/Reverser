// samples/PointCloud.cpp
// Struct-heavy geometry helpers; exercises this-like pointers and math.
#include <cmath>
#include <cstdio>
#include <vector>

struct Point {
    double x;
    double y;
    const char* label;
};

static double distance(const Point& a, const Point& b) {
    const double dx = a.x - b.x;
    const double dy = a.y - b.y;
    return std::sqrt(dx * dx + dy * dy);
}

static int nearest_index(const std::vector<Point>& pts, const Point& query) {
    if (pts.empty()) {
        return -1;
    }
    int best = 0;
    double best_d = distance(pts[0], query);
    for (int i = 1; i < static_cast<int>(pts.size()); ++i) {
        const double d = distance(pts[i], query);
        if (d < best_d) {
            best_d = d;
            best = i;
        }
    }
    return best;
}

static void print_point(const Point& p) {
    std::printf("Point(%s)=%.2f,%.2f\n", p.label ? p.label : "?", p.x, p.y);
}

static double path_length(const std::vector<Point>& pts) {
    double total = 0.0;
    for (size_t i = 1; i < pts.size(); ++i) {
        total += distance(pts[i - 1], pts[i]);
    }
    return total;
}

int main() {
    std::vector<Point> cloud = {
        {0.0, 0.0, "origin"},
        {3.0, 4.0, "a"},
        {6.0, 8.0, "b"},
        {-1.0, 2.5, "c"},
    };
    Point query{2.0, 2.0, "query"};

    std::printf("=== PointCloud ===\n");
    print_point(query);
    const int idx = nearest_index(cloud, query);
    if (idx >= 0) {
        std::printf("Nearest index: %d\n", idx);
        print_point(cloud[static_cast<size_t>(idx)]);
        std::printf("Distance: %.4f\n", distance(cloud[static_cast<size_t>(idx)], query));
    }
    std::printf("Path length: %.4f\n", path_length(cloud));
    return idx >= 0 ? 0 : 2;
}
