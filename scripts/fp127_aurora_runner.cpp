/** @file
 *  Aurora / libiop runner for the BDEC-R1CS wire format v1 ("BR1S").
 *
 *  Reads a .bdec-r1cs file produced by `src/bin/emit_aurora_r1cs.rs`,
 *  constructs a libiop::r1cs_constraint_system<fp127_Fq2>, runs
 *  aurora_snark_prover + aurora_snark_verifier, and prints a one-line
 *  JSON report suitable for automation.
 *
 *  Build / run: scripts/fp127_aurora_runner.sh
 */

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <libff/algebra/curves/fp127/fp127_fields.hpp>
#include <libff/common/profiling.hpp>

#include "libiop/bcs/bcs_common.hpp"
#include "libiop/bcs/hashing/hash_enum.hpp"
#include "libiop/bcs/hashing/hashing.hpp"
#include "libiop/relations/r1cs.hpp"
#include "libiop/relations/variable.hpp"
#include "libiop/snark/aurora_snark.hpp"

using FieldT = libff::fp127_Fq2;
using BaseFp = libff::fp127_Fq;
using HashT  = libiop::binary_hash_digest;

namespace {

static constexpr uint32_t EXPECT_VERSION      = 1;
static constexpr uint32_t EXPECT_FIELD_ID     = 1;   // Fp127 coeffs embedded in Fp2
static constexpr uint32_t EXPECT_ELEM_BYTES   = 16;

struct WireReader {
    const uint8_t *p;
    const uint8_t *end;

    explicit WireReader(const std::vector<uint8_t> &buf)
        : p(buf.data()), end(buf.data() + buf.size()) {}

    void require(size_t n, const char *what) {
        if (static_cast<size_t>(end - p) < n) {
            std::ostringstream oss;
            oss << "wire: short read (" << what << "); need " << n
                << " have " << (end - p);
            throw std::runtime_error(oss.str());
        }
    }
    uint32_t read_u32() {
        require(4, "u32");
        uint32_t v;
        std::memcpy(&v, p, 4);
        p += 4;
        return v;
    }
    uint64_t read_u64() {
        require(8, "u64");
        uint64_t v;
        std::memcpy(&v, p, 8);
        p += 8;
        return v;
    }
    void read_bytes(void *out, size_t n, const char *what) {
        require(n, what);
        std::memcpy(out, p, n);
        p += n;
    }
};

// Build an fp127_Fq from 16 canonical little-endian bytes. libff's bigint<2>
// on a 64-bit host stores two mp_limb_t (uint64_t) in little-endian limb order,
// which is exactly the byte layout produced by Rust's
// `u128::to_le_bytes()`. We verify the bit-width assumption at run-time.
FieldT fp2_from_le16(const uint8_t bytes[16]) {
    static_assert(sizeof(mp_limb_t) == 8 || sizeof(mp_limb_t) == 4,
                  "fp127 runner assumes 8- or 4-byte mp_limb_t");
    libff::bigint<libff::fp127_q_limbs> big; // zero-initialised
    std::memcpy(&big.data[0], bytes, 16);
    BaseFp c0(big);                  // applies Montgomery conversion internally
    return FieldT(c0, BaseFp::zero());
}

std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("cannot open " + path);
    ifs.seekg(0, std::ios::end);
    const std::streamsize sz = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!ifs.read(reinterpret_cast<char *>(buf.data()), sz)) {
        throw std::runtime_error("read failed: " + path);
    }
    return buf;
}

struct LoadedR1CS {
    libiop::r1cs_constraint_system<FieldT> cs;
    libiop::r1cs_primary_input<FieldT>     primary;
    libiop::r1cs_auxiliary_input<FieldT>   auxiliary;
    uint64_t wire_num_variables;       // includes const-1
    uint64_t wire_num_inputs;
    uint64_t wire_num_constraints;
};

LoadedR1CS load_wire(const std::string &path) {
    std::vector<uint8_t> buf = read_file(path);
    WireReader r(buf);

    // --- header ---
    uint8_t magic[4];
    r.read_bytes(magic, 4, "magic");
    if (std::memcmp(magic, "BR1S", 4) != 0)
        throw std::runtime_error("bad magic (expected BR1S)");
    const uint32_t version    = r.read_u32();
    const uint32_t field_id   = r.read_u32();
    const uint32_t elem_bytes = r.read_u32();
    if (version    != EXPECT_VERSION)
        throw std::runtime_error("unsupported version");
    if (field_id   != EXPECT_FIELD_ID)
        throw std::runtime_error("unsupported field_id");
    if (elem_bytes != EXPECT_ELEM_BYTES)
        throw std::runtime_error("unexpected elem_bytes");

    const uint64_t num_variables   = r.read_u64(); // incl. const-1
    const uint64_t num_inputs      = r.read_u64();
    const uint64_t num_constraints = r.read_u64();
    if (num_variables < 1)
        throw std::runtime_error("num_variables must include const-1");

    // --- constraints ---
    LoadedR1CS out;
    out.wire_num_variables   = num_variables;
    out.wire_num_inputs      = num_inputs;
    out.wire_num_constraints = num_constraints;

    // libiop's cs.num_variables() counts "real" variables (no const-1).
    out.cs.primary_input_size_   = static_cast<size_t>(num_inputs);
    out.cs.auxiliary_input_size_ =
        static_cast<size_t>(num_variables - 1 - num_inputs);

    for (uint64_t i = 0; i < num_constraints; ++i) {
        libiop::linear_combination<FieldT> rows[3];
        for (int row = 0; row < 3; ++row) {
            const uint32_t nnz = r.read_u32();
            for (uint32_t k = 0; k < nnz; ++k) {
                const uint32_t var_idx = r.read_u32();
                if (var_idx >= num_variables) {
                    throw std::runtime_error("var_idx out of range");
                }
                uint8_t coeff_bytes[16];
                r.read_bytes(coeff_bytes, 16, "coeff");
                const FieldT coeff = fp2_from_le16(coeff_bytes);
                rows[row].add_term(libiop::variable<FieldT>(var_idx), coeff);
            }
        }
        out.cs.add_constraint(
            libiop::r1cs_constraint<FieldT>(rows[0], rows[1], rows[2]));
    }

    // --- witness (positions 1..num_variables; const-1 implicit at idx 0) ---
    const uint64_t witness_len = num_variables - 1;
    std::vector<FieldT> assignment;
    assignment.reserve(static_cast<size_t>(witness_len));
    for (uint64_t i = 0; i < witness_len; ++i) {
        uint8_t bytes[16];
        r.read_bytes(bytes, 16, "witness");
        assignment.emplace_back(fp2_from_le16(bytes));
    }

    if (r.p != r.end) {
        std::cerr << "[runner] warning: trailing bytes in wire file: "
                  << (r.end - r.p) << "\n";
    }

    out.primary.assign(assignment.begin(), assignment.begin() + num_inputs);
    out.auxiliary.assign(assignment.begin() + num_inputs, assignment.end());
    return out;
}

void emit_json(const std::string &path,
               bool ok,
               double t_P_ms,
               double t_V_ms,
               size_t proof_bytes,
               const LoadedR1CS &loaded,
               bool zk,
               bool cs_sat,
               bool sanity_skipped) {
    std::cout << "{"
              << "\"file\":\"" << path << "\","
              << "\"result\":\""  << (ok ? "ACCEPT" : "REJECT") << "\","
              << "\"zk\":" << (zk ? "true" : "false") << ","
              << "\"cs_satisfied\":" << (cs_sat ? "true" : "false") << ","
              << "\"sanity_check_skipped\":" << (sanity_skipped ? "true" : "false") << ","
              << "\"num_variables_incl_const1\":" << loaded.wire_num_variables << ","
              << "\"num_inputs\":"                << loaded.wire_num_inputs << ","
              << "\"num_constraints\":"           << loaded.wire_num_constraints << ","
              << "\"t_P_ms\":"    << t_P_ms    << ","
              << "\"t_V_ms\":"    << t_V_ms    << ","
              << "\"proof_bytes\":" << proof_bytes
              << "}\n";
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " path/to/file.bdec-r1cs\n";
        return 64;
    }
    const std::string path = argv[1];

    libff::init_fp127_fields();
    libff::start_profiling();

    std::cerr << "[runner] loading " << path << " ...\n";
    LoadedR1CS loaded = load_wire(path);
    std::cerr << "[runner] wire: num_vars=" << loaded.wire_num_variables
              << " (incl const-1), num_inputs=" << loaded.wire_num_inputs
              << ", num_constraints=" << loaded.wire_num_constraints << "\n";

    // Sanity: constraint system is well-formed and satisfied.
    // SKIP_SATISFIED_CHECK=1 bypasses this so we can exercise soundness:
    // corrupt the witness, skip the precheck, and confirm Aurora REJECTs.
    const bool skip_sanity = std::getenv("SKIP_SATISFIED_CHECK") != nullptr;
    const bool is_sat = loaded.cs.is_satisfied(loaded.primary, loaded.auxiliary);
    if (!is_sat) {
        if (!skip_sanity) {
            std::cerr << "[runner] FATAL: R1CS not satisfied by wire assignment\n";
            return 2;
        }
        std::cerr << "[runner] WARNING: R1CS UNSATISFIED (SKIP_SATISFIED_CHECK=1) "
                     "-- proceeding; Aurora verifier should REJECT.\n";
    }

    // Aurora parameters: mirror probe's safe defaults. Caller can flip ZK via env.
    const size_t security_level      = 128;
    const bool   make_zk             = std::getenv("ZK") != nullptr;
    // Upstream libiop examples use RS_extra_dimensions=5 with and without ZK;
    // bumping it for ZK was a mistake that exploded the FRI domain to 2^27
    // and OOM-killed the prover. Leave at 5 — the masking polys fit.
    const size_t RS_extra_dimensions = 5;
    const size_t fri_localization    = 2;
    std::cerr << "[runner] make_zk=" << (make_zk ? "true" : "false")
              << " RS_extra_dimensions=" << RS_extra_dimensions << "\n";

    libiop::aurora_snark_parameters<FieldT, HashT> params(
        security_level,
        libiop::LDT_reducer_soundness_type::proven,
        libiop::FRI_soundness_type::heuristic,
        libiop::blake2b_type,
        fri_localization,
        RS_extra_dimensions,
        make_zk,
        libiop::multiplicative_coset_type,
        loaded.cs.num_constraints(),
        loaded.cs.num_variables());

    std::cerr << "[runner] Aurora prover ...\n";
    auto t0 = std::chrono::steady_clock::now();
    libiop::aurora_snark_argument<FieldT, HashT> proof =
        libiop::aurora_snark_prover<FieldT, HashT>(
            loaded.cs, loaded.primary, loaded.auxiliary, params);
    auto t1 = std::chrono::steady_clock::now();
    const double t_P_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    const size_t proof_bytes = proof.size_in_bytes();

    std::cerr << "[runner] Aurora verifier ...\n";
    auto t2 = std::chrono::steady_clock::now();
    const bool ok = libiop::aurora_snark_verifier<FieldT, HashT>(
        loaded.cs, loaded.primary, proof, params);
    auto t3 = std::chrono::steady_clock::now();
    const double t_V_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    emit_json(path, ok, t_P_ms, t_V_ms, proof_bytes, loaded,
              make_zk, is_sat, skip_sanity);
    return ok ? 0 : 1;
}
