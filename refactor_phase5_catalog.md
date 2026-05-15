# Phase 3 Catalog — Public Input Migration Plan

Enumerate every reference to `signature.*` and `message` in `build_loquat_r1cs_pk_witness_inner` and helpers (`enforce_transcript_relations_field_native`, `enforce_ldt_queries`). Classify each as the migration action for Phase 5.

Notation:
- **PI**: should become a public input variable (allocated via `alloc_public`, indexed in `[1, num_inputs]`)
- **W**: stays as private witness
- **C→PI**: currently a constant baked into matrix coefficients; needs to become a PI variable, with the constraints rewritten to read from the variable
- **W→PI**: currently allocated as a witness variable; just needs to be moved to the PI section of the assignment vector

## Public Inputs (assembly order matters — these become the R1CS instance vector)

| # | Source | Encoding | Count | Current state | Action |
|---|---|---|---|---|---|
| 1 | `message` (32 bytes) | bytes → 32 byte vars | 32 bytes | constant via `bytes_from_constants` ([line 2302](src/snarks/loquat_r1cs.rs:2302)) | C→PI |
| 2 | `signature.message_commitment` | `digest32_to_fields` → 2 F | 2 | constant via `enforce_digest_equals_bytes` ([line 2304](src/snarks/loquat_r1cs.rs:2304)) and `append_digest32_as_fields` ([line 3520](src/snarks/loquat_r1cs.rs:3520)) | C→PI |
| 3 | `signature.root_c` | `digest32_to_fields` → 2 F | 2 | constant in transcript absorb ([line 3521](src/snarks/loquat_r1cs.rs:3521)) | C→PI |
| 4 | `signature.t_values` | bool field-element | m·n | witness-alloc with `enforce_boolean` ([line 2315-2323](src/snarks/loquat_r1cs.rs:2315)) | W→PI |
| 5 | `signature.o_values` | F | n·m | witness-alloc ([line 2334-2343](src/snarks/loquat_r1cs.rs:2334)) | W→PI |
| 6 | `signature.mu.c0`, `signature.mu.c1` | F × 2 | 2 | witness-alloc ([line 2308-2309](src/snarks/loquat_r1cs.rs:2308)) | W→PI |
| 7 | `signature.s_sum.c0`, `signature.s_sum.c1` | F × 2 | 2 | witness-alloc ([line 2424](src/snarks/loquat_r1cs.rs:2424)) and `FieldVar::constant` in transcript absorb ([line 3656-3657](src/snarks/loquat_r1cs.rs:3656)) — DOUBLY allocated | W→PI (de-duplicate) |
| 8 | `signature.root_s` | `digest32_to_fields` → 2 F | 2 | constant in transcript absorb ([line 3655](src/snarks/loquat_r1cs.rs:3655)) | C→PI |
| 9 | `signature.root_h` | `digest32_to_fields` → 2 F | 2 | constant in transcript absorb ([line 3662](src/snarks/loquat_r1cs.rs:3662)) | C→PI |
| 10 | `signature.pi_us.claimed_sum.c0`, `.c1` | F × 2 | 2 | witness-alloc ([line 2361](src/snarks/loquat_r1cs.rs:2361)) | W→PI |
| 11 | `signature.pi_us.round_polynomials[r].c0.c0`, `.c0.c1`, `.c1.c0`, `.c1.c1` | F × 4 per round | 4 × num_rounds | witness-alloc ([line 2370-2376](src/snarks/loquat_r1cs.rs:2370)) | W→PI |
| 12 | `signature.pi_us.final_evaluation.c0`, `.c1` | F × 2 | 2 | witness-alloc ([line 2407](src/snarks/loquat_r1cs.rs:2407)) | W→PI |
| 13 | `signature.ldt_proof.commitments[layer]` | `digest32_to_fields` → 2 F per layer | 2 × (r+1) | constant in transcript absorb ([line 3686, 3699](src/snarks/loquat_r1cs.rs:3686)) | C→PI |
| 14 | `signature.ldt_proof.openings[q].position` | F | κ | constant in linear constraint ([line 3738](src/snarks/loquat_r1cs.rs:3738)) — B-Lite KEPT binding | C→PI |
| 15 | `signature.ldt_proof.openings[q].codeword_chunks[layer]` | F2 per element | κ × (r+1) × leaf_arity | witness-alloc ([line 3142-3144](src/snarks/loquat_r1cs.rs:3142)) | W→PI |
| 16 | `signature.ldt_proof.openings[q].auth_paths[layer]` | bytes | κ × (r+1) × log_branches × 32 | constant in `merkle_path_opening_fields` (need to verify) | C→PI |
| 17 | `signature.query_openings[q].c_prime_chunk[off][j]` | F2 | κ × leaf_arity × n | witness-alloc | W→PI |
| 18 | `signature.query_openings[q].s_chunk[off]` | F2 | κ × leaf_arity | witness-alloc | W→PI |
| 19 | `signature.query_openings[q].h_chunk[off]` | F2 | κ × leaf_arity | witness-alloc | W→PI |
| 20 | `signature.e_vector[i]` (real-only) | F | 8 | currently constant in LDT f0 ([line 3290-3294](src/snarks/loquat_r1cs.rs:3290)) — B-Lite carve-out | C→PI |
| 21 | `signature.c_cap_nodes` / `s_cap_nodes` / `h_cap_nodes` (if non-empty) | bytes | varies | constant in cap reconstruction ([line 2874-2879](src/snarks/loquat_r1cs.rs:2874)) | C→PI (or skip if always empty) |
| 22 | `signature.ldt_proof.cap_nodes[layer]` (if non-empty) | bytes | varies | constant ([line 2891-2898](src/snarks/loquat_r1cs.rs:2891)) | C→PI (or skip) |

**Estimated PI vector size**: 32 + 2 + 2 + m·n + n·m + 2 + 2 + 2 + 2 + 2 + 4·rounds + 2 + 2(r+1) + κ + 2κ(r+1)·leaf_arity + κ·(r+1)·log_branches·32 + κ·leaf_arity·n + 2κ·leaf_arity + κ·leaf_arity + 8 + caps...

For typical Loquat tiny params (m=4, n=4, r=10, κ=2, leaf_arity=8, rounds=4): ≈ 32+2+2+16+16+2+2+2+2+2+16+2+22+2+352+~640+128+32+16+8 ≈ ~1,300 field elements. Plus auth_path bytes ≈ 2 × 11 × 4 × 32 = 2,816 bytes ≈ 88 fields.

Total: roughly 1,400-2,000 PI elements for tiny. For paper-size (m=16, n=16, r=18, κ=8): ~10,000-20,000 PI elements. Big but acceptable.

## Witness-only (stays in witness vector)

| Source | Encoding | Count | Notes |
|---|---|---|---|
| `public_key` (pk) | bool field-element | params.l | The thing we're proving knowledge of. SOLE witness in this circuit (apart from intermediate compute vars). |
| Intermediate compute vars (from FS in-circuit derivation, QR products, sumcheck folds, FRI fold powers, etc.) | F / F2 | thousands | Allocated by builder during constraint construction. |

## Phase 5 Sub-tasks (in dependency order)

### 5.0 Pre-flight
- Add `alloc_public(value)` API to `R1csBuilder` (Phase 4).
- Define a `LoquatPublicInputs` struct that holds all the FieldVars/F2Vars listed in the table above, allocated in deterministic order.

### 5.1 Single-pass PI allocation
- New function `LoquatPublicInputs::allocate(builder, message, signature, params) -> Self` runs at the start of `build_loquat_r1cs_pk_witness_inner`, BEFORE `builder.finalize_public_inputs()`.
- Allocates every entry in the table above as a public input variable, populating witness values from the message/signature.
- Order matters — once locked, the verifier expects this exact ordering. Document it.

### 5.2 Migrate W→PI sites (mechanical)
For each W→PI row in the table, replace `builder.alloc(value)` / `builder.alloc_f2(value)` with `pi.X.idx` / `pi.X` reads.
Sites to update: lines 2308, 2315-2323, 2334-2343, 2361, 2370-2376, 2407, 2424, 3142-3144, query_openings allocation in `enforce_ldt_queries`.

### 5.3 Migrate C→PI sites (touches transcript and LDT bodies)
- **Digests** (root_c, root_s, root_h, message_commitment, ldt_proof.commitments[]): replace `digest32_to_fields(constant_bytes)` and `FieldVar::constant(...)` calls with reads of `pi.root_c_fields` etc.
- **e_vector**: replace `signature.e_vector[i]` constants in f0 reconstruction with `pi.e_vector_real[i]` FieldVars; need a new `enforce_f2_var_lincomb_eq` helper or inline f2_mul chain.
- **Query positions**: replace `signature.ldt_proof.openings[q].position` constant with `pi.query_positions[q]` FieldVar; the linear constraint at line 3738 becomes a constraint between two FieldVars (still 1 row).
- **Auth paths**: `merkle_path_opening_fields` currently takes `path: &[Vec<u8>]` (constant bytes). Either (a) pass auth path bytes via PI as 32-byte chunks, or (b) refactor to take FieldVars.

### 5.4 i_indices in-circuit multiplexer (the big one)
Currently `transcript_data.i_indices[j*m+i]` is a `usize` used as an array index into `pk_var_indices` ([line 2336](src/snarks/loquat_r1cs.rs:2336)). For C, this must become an in-circuit selector.

Options:
- **Option A — One-hot multiplexer**: For each (j,i) QR check, allocate `params.l` boolean selector variables, constrain exactly one to be 1 (sum=1), constrain `selected_pk = Σ s_l · pk_l`. Cost: `params.l + 1` constraints per check + `params.l` mul constraints for the sum. With 400 checks × 1024 pk-bits, ~410K constraints — too expensive.
- **Option B — Binary tree multiplexer**: For each (j,i), use the in-circuit `i_index_low_var` (already a FieldVar from Phase 1.1) and bit-decompose it. Walk a binary tree of muxes (log2(params.l) layers, each layer halves). Cost: ~log2(params.l) muxes per check. With params.l=1024 → 10 layers × 400 checks = 4000 mux ops. Each mux is ~2 mul constraints. ~8000 constraints. Much better.
- **Option C — Lookup table via random linear combination**: Use Plookup-style techniques. Aurora doesn't natively support lookups, would need encoding.

**Recommendation**: Option B (binary tree multiplexer). Plan to implement in Phase 5.4.

### 5.5 In-circuit Q̂ matrix (Lagrange interpolation gadget)
`compute_q_hat_on_u(params, transcript_data)` ([line 4167+](src/snarks/loquat_r1cs.rs:4167)) computes Q̂ natively. To make it in-circuit:
- Q̂ is a Lagrange interpolation of `(I_l, q_l)` pairs over the H domain, then evaluation on the U domain.
- All inputs to Q̂ are now FieldVars (lambda, epsilon, i_indices), so output Q̂ matrix is FieldVars.
- Use the standard "barycentric Lagrange evaluation" gadget. Cost: O(|H|·|U|) muls. Very expensive (could be 100K+ constraints for paper params).

**Alternative**: keep Q̂ partially native — feed Q̂ values as PI (committed via signature.q_hat_on_u, except the signature doesn't currently expose Q̂...). This requires either (a) adding Q̂ to the signature (changes wire format), or (b) deriving Q̂ from signature components committed via Merkle (deeper restructuring).

**Decision pending**: defer detailed Q̂ design until Phase 5.5; for now mark it as the highest-cost item.

### 5.6 e_vector in f0 reconstruction
[Line 3290-3304](src/snarks/loquat_r1cs.rs:3290) computes `c_coeff = e_vector[0] + e_vector[4] * x.pow(exp[0])` then uses c_coeff as F2 coefficient in `enforce_f2_const_lincomb_eq`. With e_vector as FieldVars (from PI), this becomes:
- `c_coeff_var = e_vector_real[0] + e_vector_real[4] * x.pow(exp[0])_const` — 1 mul_const + 1 add = 2 constraints (FieldVar real)
- Use c_coeff_var as F2Var coefficient (with c1=0) in a new `enforce_f2_var_lincomb_eq` helper.

### 5.7 z·ε·Q̂ coefficient in f' reconstruction
[Line 3173, 3238](src/snarks/loquat_r1cs.rs:3173) computes `coeff = z * epsilon[j] * q_hat[j][global_idx]`. With z as FieldVar (PI-bound from FS), epsilon as FieldVar (Phase 1.1), q_hat as FieldVar (from 5.5), this becomes:
- `z_eps = field_mul(z_var, epsilon_var)` — 1 mul (real-only F)
- `coeff = field_mul(z_eps, q_hat_var)` — 1 mul (could be F2 if Q̂ is F2)
- Use coeff as F2Var coefficient.

## Risks for Phase 5

1. **PI vector size**: large public inputs increase verifier time linearly. Acceptable but document.
2. **i_indices multiplexer constraint cost**: Option B (binary tree) is the smart choice, but implementation is non-trivial.
3. **Q̂ in-circuit**: highest complexity item. May need to compromise with a "Q̂ committed via signature digest, exposed as PI" model that doesn't reconstruct Q̂ in-circuit but verifies its hash matches.
4. **libiop FFI compatibility (Phase 6)**: assumes the C-side accepts a non-empty PI vector. Need to verify before committing.
5. **Auth path encoding**: 32-byte chunks per node; lots of PI bytes. Could pack 2 fields per chunk.

## Stop-points

- After Phase 5.3 (digests + e_vector + query positions + W→PI): substantial progress, but i_indices and Q̂ still constants. R1CS structure NOT yet fully signature-independent.
- After Phase 5.4 (i_indices multiplexer): pk selection is in-circuit. Q̂ still native.
- After Phase 5.5+ (Q̂ in-circuit): full C achieved structurally. Then Phase 6 wires FFI.
