// samples/XorCipher.cpp
// Byte XOR round-trip; exercises loops, buffers, cstdio.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static void xor_inplace(std::vector<unsigned char>& buf, unsigned char key) {
    for (auto& b : buf) {
        b = static_cast<unsigned char>(b ^ key);
    }
}

static std::vector<unsigned char> to_bytes(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

static std::string from_bytes(const std::vector<unsigned char>& buf) {
    return std::string(buf.begin(), buf.end());
}

static void print_hex(const char* title, const std::vector<unsigned char>& buf) {
    std::printf("%s (%zu bytes): ", title, buf.size());
    for (unsigned char b : buf) {
        std::printf("%02X", b);
    }
    std::printf("\n");
}

static bool roundtrip_ok(const std::string& plain, unsigned char key) {
    auto buf = to_bytes(plain);
    xor_inplace(buf, key);
    print_hex("cipher", buf);
    xor_inplace(buf, key);
    const std::string back = from_bytes(buf);
    std::printf("restored: %s\n", back.c_str());
    return back == plain;
}

int main(int argc, char** argv) {
    std::string plain = "SecretPayload-42";
    unsigned char key = 0x5A;
    if (argc >= 2) {
        plain = argv[1];
    }
    if (argc >= 3) {
        key = static_cast<unsigned char>(std::strtoul(argv[2], nullptr, 0));
    }

    std::printf("=== XorCipher ===\n");
    std::printf("key=0x%02X\n", key);
    std::printf("plain: %s\n", plain.c_str());
    const bool ok = roundtrip_ok(plain, key);
    if (!ok) {
        std::printf("ERROR: round-trip failed\n");
        return 1;
    }
    std::printf("OK: round-trip matched\n");
    return 0;
}
