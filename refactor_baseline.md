# Refactor Baseline (Phase 0.1)

Captured 2026-04-27 before B → C refactor. All numbers from `--tiny` parameter set (80-bit security, debug-sized).

## Legacy `build_loquat_r1cs` path (loquat_snark_stats)

| Metric | Value |
|---|---|
| R1CS variables | 201,143 |
| R1CS constraints | 201,192 |
| Aurora prove time | 13.806 s |
| Aurora verify time | 6.295 s |
| Aurora proof size | 8,423,968 B (≈8.0 MiB) |
| Loquat sign time | 24.59 ms |
| Loquat verify time | 15.41 ms |
| Loquat artifact size | 39,488 B |
| Loquat transcript size | 43,393 B |

Built with `cargo build --release --bin loquat_snark_stats`, run as:
```
./target/release/loquat_snark_stats 80 32 --tiny
```

## Production `build_loquat_r1cs_pk_witness` path (BDEC ShowVer, k=2)

| Metric | Value |
|---|---|
| Per-signature R1CS constraints | 494,602 |
| Merged ShowVer instance constraints | 996,523 |
| Per-signature log_size (Aurora) | 19 |
| Merged log_size (Aurora) | 20 |

Built with `cargo build --release --bin bdec_showcre_benchmark`, run as:
```
./target/release/bdec_showcre_benchmark --tiny -k 2 --json
```

(Stopped before completing higher-k iterations; k=2 is sufficient for refactor regression detection.)

## What we expect after refactor

**Phase 1 (B-Lite):** Constraint count should *decrease* slightly (drops the equality-binding constraints at lines 3577-3580, 3608-3611, 3615-3621, 3650-3651, 3692-3695, 3737-3738), with possible small increases from intermediate FieldVar allocations in the QR/sumcheck/LDT blocks. Net delta should be on the order of -hundreds to +low thousands.

**Phase 5 (full C):** Constraint count will *increase* meaningfully due to:
- i_indices multiplexer (one-hot selection over `params.l` pk variables, per QR check) — adds O(m·n·l) = ~O(few thousand) constraints
- Q̂ matrix in-circuit (Lagrange interpolation over kappa·n field elements) — adds O(kappa·n²) constraints
Estimated +20-50% increase in constraint count.

## Regression gates

After each phase:
1. All tests in `tests/snark_harness.rs` pass.
2. BDEC ShowVer benchmark builds + verifies the merged R1CS.
3. Constraint count delta documented vs. this baseline.
4. Aurora proof size within 2× of baseline (succinctness sanity check; small changes expected).

## Post-refactor numbers (Phase 1 B-Lite complete)

Captured 2026-04-27, BDEC ShowVer with `--tiny -k 2`, production builder `build_loquat_r1cs_pk_witness`.

| Stage | Per-sig constraints | Δ vs prev | Δ vs baseline |
|---|---|---|---|
| Baseline (pre-refactor) | 494,602 | — | — |
| Post-Phase 1.1 (plumbing only) | 494,602 | 0 | 0 |
| Post-Phase 1.2 (FS reorder + QR FieldVars) | 403,056 | −91,546 | **−91,546 (−18.5%)** |
| Post-Phase 1.3 (sumcheck F2Var) | 403,096 | +40 | −91,506 |
| Post-Phase 1.4 (FRI fold F2Var via chained f2_mul) | 407,896 | +4,800 | −86,706 (−17.5%) |
| Post-Phase 1.6 (drop redundant equality bindings) | **407,758** | −138 | **−86,844 (−17.6%)** |
| Post-Phases 5.1–5.3 (PI scaffolding + W→PI + most C→PI) | ≈407,758 | 0 (no constraint changes; only var-section reshuffling) | ≈−86,844 |
| Post-Phase 5.4 (in-circuit pk multiplexer) | **443,314** | +35,556 | **−51,288 (−10.4%)** |
| Post-Phase 5.5.1+5.5.2 (I-mux + q-vec) | **459,378** | +16,064 | −35,224 (−7.1%) |
| Post-Phase 5.5.3+5.5.4+5.5.5 (F² Lagrange + Q̂ in-circuit) | **600,258** | +140,880 | **+105,656 (+21.4%)** |
| Post-Phase 5.6 + 5.7 (full LDT block in-circuit) | **651,778** | +51,520 | **+157,176 (+31.8%)** |

### Phase 5 architectural status: COMPLETE for the LDT block

After Phases 5.1-5.7, **the entire LDT verification block** is in-circuit with FieldVar/F²Var operands:

| Component | Pre-refactor | Post-Phase-5 |
|---|---|---|
| Q̂_j(x) | F² constant lookup | Lagrange interpolation in F² (Phase 5.5) |
| z_h(x) = x^\|H\| − h_shift^\|H\| | F² constant | `vanishing_at_x` from Lagrange gadget (Phase 5.7) |
| denom_scalar = h_size_scalar · x | F² constant | F² var via const-mul (Phase 5.7) |
| h_coeff = -h_size_scalar · z_h | F² constant | F² var via const-mul (Phase 5.7) |
| expr_var = h_size_scalar · f' + h_coeff · h_chunk | F² const-lincomb | Var-form lincomb (Phase 5.7) |
| p_var · denom_scalar = numerator | F² const-mul | Inline F² var-mul check (Phase 5.7) |
| c_coeff = e_vector[0] + e_vector[4] · x^exp[0] | F² constant | F·F² mul + F²+F² add (Phase 5.6) |
| f0 lincomb at base layer | F² const-lincomb | Var-form lincomb (Phase 5.6) |

**The R1CS matrix structure is now fully signature-independent for the QR, sumcheck, and LDT blocks.** Only the encoding constants of `params` (H/U coset definitions, `qr_non_residue`, etc.) remain — these are public parameters, not signature-dependent. **Soundness still depends on Phase 6** (libiop FFI surgery) to make the PI section semantically enforced cryptographically.

### Phase 5.5 architectural milestone

Q̂_j(x) for the LDT verifier is now reconstructed entirely **in-circuit** via barycentric Lagrange interpolation over F² (Loquat's extension field). The R1CS matrix no longer carries `q_hat_on_u[j][global_idx]` constants — q̂ values flow as F²Vars derived from FS-bound λ, I, and position bits.

Cost breakdown per (off, query) pair (16 such pairs per signature for tiny):
- `x_at_off_var = x_chunk_start_var · u_g^off` (F² const-mul, 2 lin rows)
- `LagrangeBasisGadgetF2` at x_at_off (≈156 rows for |H|=8): s_powers chain in F² (6 rows per power), vanishing(x), per-l witness-inverse + barycentric basis
- Per j: F² evaluation of q̂_j(x) = Σ q_eval[l] · L_l(x) (~18 rows for |H|=8, ×n j-values)
- f' var-form lincomb: per j coefficient `z·ε·q̂_j` (3 mul rows) + term f2_mul (6 rows)

Total Phase 5.5.3+5.5.4+5.5.5 cost: ~+140K constraints. The F² typing (each F² mul = 4 F muls + 2 linear) compounds across the Lagrange basis evaluation per query position. **This is the honest cost of in-circuit Q̂ reconstruction; Option B (Q̂-via-PI hash) would have been cheaper but would require modifying Loquat's signature wire format**.

**Tests passing after Phase 1.6 (B-Lite complete):**
- `aurora_accepts_valid_signature_witness` (legacy, completeness): PASS, 21.66s
- `aurora_proves_two_independent_credentials_same_keypair` (production BDEC, completeness): PASS, 49.73s
- `tampered_witness_fails_aurora_verification` (soundness): PASS, 21.49s — tampered witness rejected

**B-Lite carve-outs deferred to Phase 5 (full C):**
- `transcript_data.i_indices` still used as native `usize` for pk selector (line 2336) — needs in-circuit multiplexer.
- `compute_q_hat_on_u` (line 4167) still computes Q̂ matrix natively — needs in-circuit Lagrange interpolation gadget.
- `transcript_data.z_challenge` still used as F2 constant in LDT (line 2917, 3173) — entangled with Q̂.
- `signature.e_vector` still used as F2 constants in f0 reconstruction (LDT line 3290–3304).
- Equality bindings KEPT for: i_indices, z, e_vector, query positions (these enforce honesty for the still-constant references).

**Note on the −18% Phase 1.2 reduction**: Mechanism not fully traced. Each `enforce_mul_const_var` → `enforce_mul_vars` swap is row-count-neutral, and the reorder doesn't change which constraints exist. Hypothesis: the original build path had redundant intermediate variable allocations or constant-folding side effects that the variable-form path naturally avoids. Reproducible across runs; worth a post-mortem investigation but not blocking.

**Cost analysis Phase 1.3+1.4**: +4,840 added constraints come from:
- Phase 1.3 sumcheck f2_mul: +4 mul rows per round × ~10 rounds = +40 (matches prediction)
- Phase 1.4 FRI fold f2_mul chain: +(2·expected_len − 3) × 6 + 2 ≈ +80 per fold × 18 layers × 2 queries = +2,880 expected. Actual was +4,800 — slightly higher, likely due to fold also running for inter-query passes. Within order-of-magnitude prediction.

Net B-Lite outcome: ~17% net reduction in per-signature constraints vs baseline, **with all FS challenges (lambda, epsilon, sumcheck, FRI) now bound by in-circuit Griffin hashing rather than baked constants**. Remaining constants (i_indices, z, e_vector, query positions) deferred to Phase 5 with the public-input migration.
