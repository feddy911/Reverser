#include <cmath>
#include <iostream>

void print_coordinates(int x, int y)
{
    std::cout << std::showpos
        << "(x:" << x << ", y:" << y << ") cartesian is "
        << "(r:" << std::hypot(x, y)
        << ", phi:" << std::atan2(y, x) << ") polar\n";
}

int main()
{
    // normal usage: the signs of the two arguments determine the quadrant
    print_coordinates(+1, +1); // atan2( 1,  1) =  +pi/4, Quad I
    print_coordinates(-1, +1); // atan2( 1, -1) = +3pi/4, Quad II
    print_coordinates(-1, -1); // atan2(-1, -1) = -3pi/4, Quad III
    print_coordinates(+1, -1); // atan2(-1,  1) =  -pi/4, Quad IV

    // special values
    std::cout << std::noshowpos
        << "atan2(0, 0) = " << atan2(0, 0) << '\n'
        << "atan2(0,-0) = " << atan2(0, -0.0) << '\n'
        << "atan2(7, 0) = " << atan2(7, 0) << '\n'
        << "atan2(7,-0) = " << atan2(7, -0.0) << '\n';
}