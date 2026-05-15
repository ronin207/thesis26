/** @file
 *  Compilation + end-to-end probe for Aurora / libiop over Fp2_M127.
 *
 *  Goal: confirm that `aurora_snark_prover / aurora_snark_verifier` template-
 *  instantiate cleanly over the new libiop::fp127_Fq2 field, produce a proof
 *  on a small synthesised R1CS, and that the verifier accepts.
 *
 *  Build / run: scripts/fp127_aurora_probe.sh
 */

#include <chrono>
#include <cstdio>
#include <iostream>

#include <libff/algebra/curves/fp127/fp127_fields.hpp>
#include <libff/common/profiling.hpp>

#include "libiop/snark/aurora_snark.hpp"
#include "libiop/bcs/bcs_common.hpp"
#include "libiop/bcs/hashing/hash_enum.hpp"
#include "libiop/bcs/hashing/hashing.hpp"
#include "libiop/relations/examples/r1cs_examples.hpp"

using FieldT = libff::fp127_Fq2;
using HashT  = libiop::binary_hash_digest;

int main(int argc, char **argv)
{
    libff::init_fp127_fields();
    libff::start_profiling();

    // Tunables (small so we actually finish):
    //   log2 num_constraints = 6 -> 64 constraints (plenty for a template probe)
    size_t log_n          = 6;
    size_t num_inputs     = 15;  // "k" — k+1 must be power of 2
    if (argc >= 2) log_n  = static_cast<size_t>(std::stoi(argv[1]));
    if (argc >= 3) num_inputs = static_cast<size_t>(std::stoi(argv[2]));

    const size_t n                    = (1ul << log_n);
    const size_t num_constraints      = n;
    const size_t num_variables        = n - 1;
    const size_t security_level       = 128;
    const size_t RS_extra_dimensions  = 3 + 2; // no zk -> +2
    const size_t fri_localization     = 2;
    const bool   make_zk              = false;

    std::cout << "[probe] Fp2_M127 parameters\n"
              << "  log_n              = " << log_n << "\n"
              << "  num_constraints    = " << num_constraints << "\n"
              << "  num_variables      = " << num_variables << "\n"
              << "  num_inputs         = " << num_inputs << "\n"
              << "  security           = " << security_level << " bits\n"
              << "  RS_extra_dim       = " << RS_extra_dimensions << "\n"
              << "  FRI_loc_param      = " << fri_localization << "\n"
              << "  make_zk            = " << (make_zk ? "true" : "false") << "\n"
              << "  domain_type        = multiplicative_coset\n"
              << "  hash               = blake2b (binary_hash_digest)\n";

    std::cout << "[probe] generating R1CS example ... " << std::flush;
    libiop::r1cs_example<FieldT> ex = libiop::generate_r1cs_example<FieldT>(
        num_constraints, num_inputs, num_variables);
    std::cout << "done.\n";

    const bool sat = ex.constraint_system_.is_satisfied(
        ex.primary_input_, ex.auxiliary_input_);
    std::cout << "[probe] R1CS satisfied? " << (sat ? "yes" : "NO") << "\n";
    if (!sat) return 2;

    libiop::aurora_snark_parameters<FieldT, HashT> params(
        security_level,
        libiop::LDT_reducer_soundness_type::proven,
        libiop::FRI_soundness_type::heuristic,
        libiop::blake2b_type,
        fri_localization,
        RS_extra_dimensions,
        make_zk,
        libiop::multiplicative_coset_type,
        ex.constraint_system_.num_constraints(),
        ex.constraint_system_.num_variables());

    std::cout << "[probe] Aurora prover ...\n";
    auto t0 = std::chrono::steady_clock::now();
    libiop::aurora_snark_argument<FieldT, HashT> proof =
        libiop::aurora_snark_prover<FieldT, HashT>(
            ex.constraint_system_, ex.primary_input_, ex.auxiliary_input_, params);
    auto t1 = std::chrono::steady_clock::now();
    const double t_P_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::cout << "[probe] Aurora verifier ...\n";
    auto t2 = std::chrono::steady_clock::now();
    const bool ok = libiop::aurora_snark_verifier<FieldT, HashT>(
        ex.constraint_system_, ex.primary_input_, proof, params);
    auto t3 = std::chrono::steady_clock::now();
    const double t_V_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    std::cout << "[probe] result                  = " << (ok ? "ACCEPT" : "REJECT") << "\n";
    std::cout << "[probe] t_P (ms)                = " << t_P_ms << "\n";
    std::cout << "[probe] t_V (ms)                = " << t_V_ms << "\n";

    return ok ? 0 : 1;
}
