// samples/GammaFn.cpp
// Arbitrary-precision Gamma via MPFR + integer factorial check via GMP.
// Eval sample (MyCollatz-level library types). Do not write sanitizer recipes from it.
#include <cmath>
#include <gmp.h>
#include <iostream>
#include <mpfr.h>
#include <string>
#include <vector>

struct GammaHold {
    mpfr_t z;
    mpfr_t g;
    mpfr_t lng;
    mpz_t nfact;
    mpfr_prec_t bits;
};

static std::string mpfr_to_string(const mpfr_t x, int digits) {
    mpfr_exp_t exp = 0;
    char* raw = mpfr_get_str(nullptr, &exp, 10, static_cast<std::size_t>(digits), x, MPFR_RNDN);
    if (raw == nullptr) {
        return "?";
    }
    std::string mant(raw);
    mpfr_free_str(raw);
    if (mant.empty() || mant == "@NaN@" || mant[0] == '@') {
        return mant;
    }
    const bool neg = mant[0] == '-';
    const std::string digits_only = neg ? mant.substr(1) : mant;
    if (digits_only.empty()) {
        return "0";
    }
    std::string out = neg ? "-" : "";
    if (exp <= 0) {
        out += "0.";
        out.append(static_cast<std::size_t>(-exp), '0');
        out += digits_only;
    } else if (static_cast<std::size_t>(exp) >= digits_only.size()) {
        out += digits_only;
        out.append(static_cast<std::size_t>(exp) - digits_only.size(), '0');
    } else {
        out += digits_only.substr(0, static_cast<std::size_t>(exp));
        out += ".";
        out += digits_only.substr(static_cast<std::size_t>(exp));
    }
    return out;
}

static std::string mpz_to_dec(const mpz_t n) {
    const std::size_t size = mpz_sizeinbase(n, 10) + 2;
    std::vector<char> buf(size);
    mpz_get_str(buf.data(), 10, n);
    return std::string(buf.data());
}

static void gamma_eval(mpfr_t out, const mpfr_t z) {
    mpfr_gamma(out, z, MPFR_RNDN);
}

static void ln_gamma_eval(mpfr_t out, const mpfr_t z) {
    mpfr_lngamma(out, z, MPFR_RNDN);
}

static void gamma_int_exact(mpz_t out, unsigned long n) {
    if (n == 0) {
        mpz_set_ui(out, 1);
        return;
    }
    mpz_fac_ui(out, n - 1);
}

static void print_gamma_table(GammaHold* h, const double* xs, int n) {
    std::cout << "=== GammaFn table ===\n";
    for (int i = 0; i < n; ++i) {
        mpfr_set_d(h->z, xs[i], MPFR_RNDN);
        gamma_eval(h->g, h->z);
        ln_gamma_eval(h->lng, h->z);
        std::cout << "x=" << xs[i]
                  << "  G=" << mpfr_to_string(h->g, 12)
                  << "  lnG=" << mpfr_to_string(h->lng, 12)
                  << "\n";
    }
}

int main() {
    GammaHold hold{};
    hold.bits = 128;
    mpfr_init2(hold.z, hold.bits);
    mpfr_init2(hold.g, hold.bits);
    mpfr_init2(hold.lng, hold.bits);
    mpz_init(hold.nfact);

    const double xs[] = {0.5, 1.0, 2.0, 5.0, 6.5};
    print_gamma_table(&hold, xs, 5);

    mpfr_set_d(hold.z, 0.5, MPFR_RNDN);
    gamma_eval(hold.g, hold.z);
    mpfr_mul(hold.z, hold.g, hold.g, MPFR_RNDN);
    const double pi_est = mpfr_get_d(hold.z, MPFR_RNDN);
    std::cout << "G(0.5)^2 ~ " << pi_est << " (pi=" << 3.141592653589793 << ")\n";

    gamma_int_exact(hold.nfact, 5);
    std::cout << "Gamma(5) exact = " << mpz_to_dec(hold.nfact) << "\n";
    std::cout << "tgamma(5) = " << std::tgamma(5.0) << "\n";

    const double err = std::fabs(pi_est - 3.141592653589793);
    mpfr_clear(hold.z);
    mpfr_clear(hold.g);
    mpfr_clear(hold.lng);
    mpz_clear(hold.nfact);
    return err < 1e-10 ? 0 : 1;
}
