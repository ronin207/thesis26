/** @file
 *  Runtime sanity check for the libff Fp127 / Fp2_M127 port.
 *
 *  Verifies that the constants initialised by libff::init_fp127_fields() and the
 *  Montgomery arithmetic built on top match the pure-Python reference in
 *  scripts/compute_fp127_constants.py.
 *
 *  Build (against an existing cargo-built libff.a):
 *      see scripts/fp127_sanity.sh
 *
 *  Emits one key=value line per probe. Compare against the reference dump
 *  produced by scripts/compute_fp127_constants.py.
 */

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>

#include <libff/algebra/curves/fp127/fp127_fields.hpp>
#include <libff/algebra/field_utils/bigint.hpp>

using libff::bigint;
using libff::fp127_Fq;
using libff::fp127_Fq2;

static std::string bigint_dec(const bigint<libff::fp127_q_limbs> &b) {
    // libff's bigint<n>::operator<< prints mpz decimal.
    std::ostringstream os;
    os << b;
    return os.str();
}

static std::string fp_dec(const fp127_Fq &x) {
    return bigint_dec(x.as_bigint());
}

int main() {
    libff::init_fp127_fields();

    std::cout << "# fp127 sanity probe (libff Fp_model + Fp2_model)\n";
    std::cout << "modulus=" << libff::fp127_modulus_q << "\n";
    std::cout << "num_bits=" << fp127_Fq::num_bits << "\n";
    std::cout << "s=" << fp127_Fq::s << "\n";
    std::cout << "Rsquared=" << fp127_Fq::Rsquared << "\n";
    std::cout << "Rcubed=" << fp127_Fq::Rcubed << "\n";
    std::cout << "inv=" << fp127_Fq::inv << "\n";
    std::cout << "euler=" << fp127_Fq::euler << "\n";
    std::cout << "t=" << fp127_Fq::t << "\n";
    std::cout << "t_minus_1_over_2=" << fp127_Fq::t_minus_1_over_2 << "\n";
    std::cout << "nqr=" << fp_dec(fp127_Fq::nqr) << "\n";
    std::cout << "nqr_to_t=" << fp_dec(fp127_Fq::nqr_to_t) << "\n";
    std::cout << "generator=" << fp_dec(fp127_Fq::multiplicative_generator) << "\n";
    std::cout << "root_of_unity=" << fp_dec(fp127_Fq::root_of_unity) << "\n";

    // --- Base field arithmetic probes ---
    // 3 * 3 = 9
    fp127_Fq three = fp127_Fq("3");
    fp127_Fq nine  = three * three;
    std::cout << "3*3=" << fp_dec(nine) << "\n";

    // 2^127 mod p  =>  since p = 2^127 - 1, 2^127 = 1.
    fp127_Fq two = fp127_Fq("2");
    fp127_Fq two_pow = two ^ static_cast<unsigned long>(127);
    std::cout << "2^127_mod_p=" << fp_dec(two_pow) << "  (expect 1)\n";

    // Fermat: a^(p-1) = 1 for any nonzero a. Use a = 5.
    fp127_Fq five = fp127_Fq("5");
    fp127_Fq fermat = five ^ fp127_Fq::euler; // a^((p-1)/2) = legendre; will square to 1
    fp127_Fq fermat_full = fermat * fermat;
    std::cout << "5^(p-1)_via_square_of_euler=" << fp_dec(fermat_full) << "  (expect 1)\n";

    // Legendre of 3 mod p: since 3 is QNR, a^((p-1)/2) = -1 = p-1.
    fp127_Fq leg3 = three ^ fp127_Fq::euler;
    std::cout << "legendre(3,p)=" << fp_dec(leg3) << "  (expect p-1)\n";

    // Inverse check: 7 * 7^{-1} = 1.
    fp127_Fq seven = fp127_Fq("7");
    fp127_Fq seven_inv = seven.inverse();
    std::cout << "7*7^-1=" << fp_dec(seven * seven_inv) << "  (expect 1)\n";

    // --- Fp2 probes ---
    std::cout << "Fp2::non_residue=" << fp_dec(fp127_Fq2::non_residue) << "\n";
    std::cout << "Fp2::s=" << fp127_Fq2::s << "\n";
    std::cout << "Fp2::t=" << fp127_Fq2::t << "\n";
    std::cout << "Fp2::Frob[0]=" << fp_dec(fp127_Fq2::Frobenius_coeffs_c1[0]) << "\n";
    std::cout << "Fp2::Frob[1]=" << fp_dec(fp127_Fq2::Frobenius_coeffs_c1[1]) << "\n";
    std::cout << "Fp2::nqr.c0=" << fp_dec(fp127_Fq2::nqr.c0) << "\n";
    std::cout << "Fp2::nqr.c1=" << fp_dec(fp127_Fq2::nqr.c1) << "\n";
    std::cout << "Fp2::nqr_to_t.c0=" << fp_dec(fp127_Fq2::nqr_to_t.c0) << "\n";
    std::cout << "Fp2::nqr_to_t.c1=" << fp_dec(fp127_Fq2::nqr_to_t.c1) << "\n";

    // U * U = non_residue = 3.  Here U = (0,1).
    fp127_Fq2 U(fp127_Fq("0"), fp127_Fq("1"));
    fp127_Fq2 Usq = U * U;
    std::cout << "U*U.c0=" << fp_dec(Usq.c0) << "  (expect 3)\n";
    std::cout << "U*U.c1=" << fp_dec(Usq.c1) << "  (expect 0)\n";

    // (1 + U) * (1 - U) = 1 - U^2 = 1 - 3 = -2 = p - 2
    fp127_Fq2 one_plus_U  (fp127_Fq("1"), fp127_Fq("1"));
    fp127_Fq2 one_minus_U (fp127_Fq("1"), -fp127_Fq("1"));
    fp127_Fq2 prod = one_plus_U * one_minus_U;
    std::cout << "(1+U)*(1-U).c0=" << fp_dec(prod.c0) << "  (expect p-2)\n";
    std::cout << "(1+U)*(1-U).c1=" << fp_dec(prod.c1) << "  (expect 0)\n";

    // Fp2 2-adicity consistency:   nqr_to_t^(2^(s-1)) != 1   but    nqr_to_t^(2^s) == 1.
    fp127_Fq2 acc = fp127_Fq2::nqr_to_t;
    for (size_t i = 0; i + 1 < fp127_Fq2::s; ++i) {
        acc = acc * acc;
    }
    // acc = nqr_to_t^(2^(s-1)); must be the unique order-2 element = -1.
    std::cout << "nqr_to_t^(2^(s-1)).c0=" << fp_dec(acc.c0) << "\n";
    std::cout << "nqr_to_t^(2^(s-1)).c1=" << fp_dec(acc.c1) << "\n";
    fp127_Fq2 top = acc * acc;
    std::cout << "nqr_to_t^(2^s).c0=" << fp_dec(top.c0) << "  (expect 1)\n";
    std::cout << "nqr_to_t^(2^s).c1=" << fp_dec(top.c1) << "  (expect 0)\n";

    // Inverse in Fp2: x * x^{-1} = 1.
    fp127_Fq2 x(fp127_Fq("11"), fp127_Fq("13"));
    fp127_Fq2 x_inv = x.inverse();
    fp127_Fq2 xone = x * x_inv;
    std::cout << "(11+13U)*inv.c0=" << fp_dec(xone.c0) << "  (expect 1)\n";
    std::cout << "(11+13U)*inv.c1=" << fp_dec(xone.c1) << "  (expect 0)\n";

    // --- Aurora-required extras: multiplicative_generator + root_of_unity ---
    std::cout << "Fp2::mult_gen.c0=" << fp_dec(fp127_Fq2::multiplicative_generator.c0) << "\n";
    std::cout << "Fp2::mult_gen.c1=" << fp_dec(fp127_Fq2::multiplicative_generator.c1) << "\n";
    std::cout << "Fp2::root_of_unity.c0=" << fp_dec(fp127_Fq2::root_of_unity.c0) << "\n";
    std::cout << "Fp2::root_of_unity.c1=" << fp_dec(fp127_Fq2::root_of_unity.c1) << "\n";

    // root_of_unity^(2^s) == 1 AND root_of_unity^(2^(s-1)) == -1 (primitivity).
    fp127_Fq2 rou = fp127_Fq2::root_of_unity;
    for (size_t i = 0; i + 1 < fp127_Fq2::s; ++i) {
        rou = rou * rou;
    }
    std::cout << "rou^(2^(s-1)).c0=" << fp_dec(rou.c0) << "\n";
    std::cout << "rou^(2^(s-1)).c1=" << fp_dec(rou.c1) << "\n";
    fp127_Fq2 rou_top = rou * rou;
    std::cout << "rou^(2^s).c0=" << fp_dec(rou_top.c0) << "  (expect 1)\n";
    std::cout << "rou^(2^s).c1=" << fp_dec(rou_top.c1) << "  (expect 0)\n";

    return 0;
}
