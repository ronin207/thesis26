# Proving-Architecture + Interaction Map (2026-06-24)

Source-grounded architecture map of every proving system in the thesis stack, plus
the four analytical interaction surfaces. Every claim is tagged **VERIFIED** (the
composition/logic was read) or **INFERRED** (deduced from naming/structure/deps — the
file to read to confirm is named). All paths are repo-relative to
`/Users/takumiotsuka/.../research/thesis`.

**Scope correction up front (load-bearing).** Two facts reorganize the rest of this map:

1. The **dedicated Griffin-Fp192 AIR precompile chip exists only in the SP1 fork**
   (`submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/`,
   stage-3 COMPLETE per `air.rs:3`, VERIFIED). In the **RISC Zero** path there is
   **no** dedicated Griffin/PRF precompile — Griffin and the PRF reach a precompile
   only indirectly, one generic 256-bit `sys_bigint` modmul per `Fp192::mul`
   (`src/primitives/field/p192.rs:463`, VERIFIED). The CLAUDE.md "3 precompile
   modules" deliverable is realized on SP1 (Griffin AIR) + the shared 256-bit modmul;
   `add`/`sub` are not precompiled on either substrate.

2. **VEIL is dead code relative to the live SP1 prover.** `slop-veil` is referenced
   only as a workspace path entry (`submodules/sp1/Cargo.toml:202`) and its own
   manifest — no crate depends on it (VERIFIED by scanning every `Cargo.toml` under
   `crates/` and `slop/crates/`). Its eval-claim guard therefore cannot fire in
   production; the SP1 ZK path is the gnark BN254 wrap, structurally separate.

---

## Architecture 1 — SP1 Hypercube prover

`submodules/sp1` @ `8bf0248bc5b6b7ba7c820253c3918ea277008641`. Naming: the small-field
STARK layer is `SP1Field` = **KoalaBear**; PCS = jagged + stacked Basefold (FRI-style);
lookups = **LogUp-GKR** (a GKR-based logup, not a permutation-column logup); ZK-wrap =
BN254 Groth16/PLONK via gnark over Go FFI.

| Component | Field | Role | file:line | Tag |
|---|---|---|---|---|
| Core STARK field | KoalaBear (`SP1Field`) | field for all core/recursion shard proofs | `crates/primitives/src/lib.rs:28` (`pub type SP1Field = KoalaBear;`) | VERIFIED |
| Extension field | KoalaBear deg-4 binomial | challenge/soundness field | `crates/primitives/src/lib.rs:31` | VERIFIED |
| Merkle/hash TCS | Poseidon2-KoalaBear width-16 | Basefold leaf commitment | `crates/hypercube/src/prover/mod.rs:22` | VERIFIED |
| Basefold config | KoalaBear deg-4 duplex | PCS config | `crates/hypercube/src/verifier/config.rs:14` | VERIFIED |
| ShardProver | KoalaBear (`GC::F`) | one shard: commit→GKR→zerocheck→PCS | `crates/hypercube/src/prover/shard.rs:650` | VERIFIED |
| Jagged PCS | KoalaBear/EF | commits variable-length MLEs | `slop/crates/jagged/src/prover.rs:106`, `:162` | VERIFIED |
| Basefold/FRI | KoalaBear | folding/commit phase under jagged | `slop/crates/basefold-prover/src/fri.rs:89`, `:118` | VERIFIED |
| LogUp-GKR | KoalaBear/EF | lookup/interaction argument | `crates/hypercube/src/prover/shard.rs:698`; builder `crates/hypercube/src/lookup/builder.rs:83,92` | VERIFIED |
| gnark-ffi wrap | BN254 | STARK → Groth16/PLONK SNARK | `crates/recursion/gnark-ffi/src/ffi/native.rs:39-44` (extern "C" `ProveGroth16Bn254`/`ProvePlonkBn254`) | VERIFIED |

**Multi-shard prove-flow (file:line hops):**
1. `crates/prover/src/worker/node/full/mod.rs:103` `prove()` → `:168`
   `prove_with_mode(..., ProofMode::Compressed)` — a `Controller` task in a
   network/worker architecture, not a monolithic fn. VERIFIED.
2. Execution split into shards: `crates/prover/src/worker/prover/core.rs:281-331` —
   each `ExecutionRecord` → a shard; `record.defer(...)` (`:326`) splits off deferred
   (precompile/memory) events; `SplitOpts` (`:14`) sizes shards. VERIFIED.
3. Per-shard proof `crates/hypercube/src/prover/shard.rs:650` `prove_shard_with_data`:
   `:680` `commit_traces` (jagged commit) → `:698` `prove_logup_gkr` (lookups) →
   `:724` `zerocheck` (constraint sumcheck) → `:771` `prove_trusted_evaluations`
   (jagged+Basefold opening) → `:782` assemble `ShardProof`. VERIFIED.
4. Shard proofs recursively verified + combined by recursion programs
   (`RecursiveShardVerifier`, `crates/prover/src/worker/prover/core.rs:130`);
   compress/shrink/wrap shapes in `crates/prover/src/shapes.rs:91,737`. Types VERIFIED;
   exact reduce-tree arity/order INFERRED — read `controller/compress.rs`.
5. ZK-wrap: `crates/prover/src/build.rs:683-685` `shrink_wrap(...)` → final SNARK
   `Groth16Bn254Prover::prove` (`crates/recursion/gnark-ffi/src/groth16_bn254.rs:54`)
   crossing into Go gnark at `crates/recursion/gnark-ffi/src/ffi/native.rs:201`. VERIFIED.

**PCS detail.** Jagged pads each table MLE to `max_log_row_count` and adds dummy
padding columns to round the committed area to a multiple of the stacking height
(`slop/crates/jagged/src/prover.rs:120-139`, VERIFIED). The dense inner PCS is stacked
Basefold over KoalaBear deg-4 duplex (`slop/crates/jagged/src/basefold.rs:16`,
VERIFIED); folding is FRI-style even/odd (`host_fold_even_odd`,
`basefold-prover/src/fri.rs:118`) over `RsCodeWord` Reed-Solomon codewords with
`BATCH_GRINDING_BITS` PoW (`basefold-prover/src/prover.rs:9`). VERIFIED.

**How a change here propagates.** Changing the field (KoalaBear→BabyBear) touches
`primitives/src/lib.rs:28` and every Basefold/Merkle config keyed on it — but the
Griffin-Fp192 chip's 192-bit modmul (`FieldOpCols`) is rendered *over the base field*,
so a base-field swap re-parameterizes the witness-limb budget, not the limb count.

---

## Architecture 2 — RISC Zero

`platforms/zkvms/risc0/`. Pinned `risc0-zkvm = "^3.0.5"` (declared `^3.0.3` in
`host/Cargo.toml:8` and `methods/guest/Cargo.toml:11`; resolved 3.0.5 at
`Cargo.lock:3075`, VERIFIED). `metal` GPU feature on (`host/Cargo.toml:8`).

| Component | Field | Role | file:line | Tag |
|---|---|---|---|---|
| risc0-zkvm | — | zkVM prover/host API | `host/Cargo.toml:8`; `Cargo.lock:3075` | VERIFIED |
| Native STARK field (BabyBear) | BabyBear (2³¹−2²⁷+1) | rv32im execution-trace field | NOT in-repo — `risc0-zkp 3.0.4` `Cargo.lock:3044` | INFERRED — read risc0-zkp `field/baby_bear.rs` |
| rv32im AIR + DEEP-ALI/FRI | BabyBear | low-degree proof | NOT in-repo — `risc0-circuit-rv32im 4.0.4` `Cargo.lock:2936` | INFERRED |
| Groth16 wrap | BN254 | final SNARK (present, NOT invoked by PLUM bins) | `risc0-groth16 3.0.4` `Cargo.lock:2996` | INFERRED |
| `Fp192::mul` precompile call | Fp192 (199-bit) | modmul via `sys_bigint(OP_MULTIPLY)` | `src/primitives/field/p192.rs:463-469` | VERIFIED |
| `Fp192::add`/`sub` | Fp192 | multi-limb BigUint, **no** precompile | `src/primitives/field/p192.rs:370-391` | VERIFIED |
| Griffin permutation | Fp192 | algebraic hash, **no** dedicated precompile (reaches `sys_bigint` only via `mul`) | `src/primitives/hash/griffin_p192.rs` | VERIFIED |
| PLUM-Griffin guest | Fp192 | proves `plum_verify` | `methods/guest/src/bin/plum_verify_griffin.rs:64-82` | VERIFIED |
| Proving (PLUM bins) | — | `default_prover().prove()`, STARK receipt | `host/src/bin/plum_host.rs:364-369` | VERIFIED |
| Proving (BDEC ShowVer) | — | `ProverOpts::succinct()`, succinct receipt | `host/src/pp2_showver.rs:378,554,560` | VERIFIED |

**Guest→host flow.** `plum_host.rs:351-361` build env → `:364` `default_prover()` →
`:365` `prover.prove(env, elf)` → guest `plum_verify_griffin.rs:64`
`plum_verify::<PlumGriffinHasher>` → every `Fp192*Fp192` hits
`p192.rs:463 sys_bigint(OP_MULTIPLY)` (gated `target_os="zkvm", feature="risc0"`,
`:451`) → guest commits journal `:82` → host `receipt.verify(id)` `:368`,
`prove_info.stats.total_cycles` `:375`. VERIFIED.

**ZK status — disclaimed and unsubstantiated in-repo.** PLUM/Griffin measurement bins
use the bare `default_prover().prove()` path (no `ProverOpts`, no `.compressed()`):
`plum_host.rs:364-369`, also `loquat_only.rs:193`, `griffin_microbench.rs:79`. The
receipt is `InnerReceipt::Succinct` (a STARK), not Groth16/PLONK. **There is NO in-repo
comment or config asserting blinding or disclaiming ZK** — the "blinding but
ZK-disclaimed" framing lives in RISC Zero's own security docs and `risc0-zkp`, not this
repo. The only ZK-adjacent in-repo fact: the default path produces succinct STARK
receipts, which are not ZK by default (mirrors the SP1 disclaimer in CLAUDE.md).

**NOT in-repo (cannot be traced from source here):** BabyBear modulus + field
arithmetic; rv32im execution AIR + DEEP-ALI + FRI; the `sys_bigint` Zirgen bigint AIR
constraint logic (per `docs/precompile_soundness/uint256_mul_for_fp192.md:31-35`, lives
in `risc0-circuit-rv32im-4.0.4/src/zirgen/{steps.rs.inc,poly_ext.rs}`); recursion/lift
and Groth16 wrap circuits; any blinding/ZK statement.

**How a change here propagates.** The RISC Zero substrate offers no dedicated
Griffin AIR, so the Griffin 91% share stays multi-limb-emulated through generic modmul
— the precompile speedup story is the SP1 fork's, not RISC Zero's.

---

## Architecture 3 — libiop SNARKs (Aurora, Fractal)

`submodules/libiop/` (C++). This is the Cell-4 OUTER circuit-SNARK reference baseline —
distinct from PLUM's inner STIR IOP (Architecture 4). Field is **Fp127** with an
**F_{p²} quadratic extension** for Loquat.

| Component | Field | Role | file:line | Tag |
|---|---|---|---|---|
| Aurora SNARK | Fp / F_{p²} | RS-encoded R1CS IOP → SNARK | `libiop/snark/aurora_snark.{hpp,tcc}` | INFERRED structure — read aurora_snark.tcc prover/verifier bodies |
| Aurora IOP | Fp | RS-encoded R1CS, univariate sumcheck + LDT | `libiop/protocols/aurora_iop.{hpp,tcc}` (or `iop/`) | INFERRED — read protocol round logic |
| BCS transform | Fp | IOP → non-interactive via Merkle + Fiat-Shamir | `libiop/bcs/bcs_{prover,verifier}.{hpp,tcc}` | INFERRED — read hashchain/round→root mapping |
| Fractal SNARK | Fp | holographic/preprocessing variant (indexer) | `libiop/snark/fractal_snark.{hpp,tcc}` | INFERRED — read indexer vs Aurora delta |
| Field Fp127 | 127-bit prime + F_{p²} | base field | thesis runner `scripts/fp127_aurora_runner.cpp`; emitter `src/bin/emit_aurora_r1cs.rs` | VERIFIED present (driver); field exact value — read runner field typedef |

*(The libiop tracing returned a clear structural picture but the per-line bodies of
`aurora_snark.tcc`/`bcs_prover.tcc` were not exhaustively read; the file paths above
are where to confirm the RS-encoding, the univariate sumcheck, and the
Merkle-root-per-round Fiat-Shamir. Treat the component roles as VERIFIED-by-structure,
the internal logic as INFERRED until those `.tcc` bodies are read.)*

**Drive path (Cell 4).** `src/bin/emit_aurora_r1cs.rs` emits a Loquat-BDEC R1CS;
`scripts/fp127_aurora_runner.cpp` feeds it to Aurora over Fp127. This is the measured
PLUM-in-Aurora *proxy* — PLUM-in-Aurora-Fp192 is NOT runnable (fp127-only harness; see
`docs/r_static_finding_20260605.md`). VERIFIED that this is a proxy, per CLAUDE.md Cell-4
note + the existing R_static finding.

**How a change here propagates.** Aurora is non-preprocessing: changing the relation
re-runs the prover from scratch (R_static ≈ 0.3 s, `docs/r_static_finding_20260605.md`);
Fractal preprocesses (indexer), so its R_static is the 0.86–18.5 s synth range / OOM at
BDEC 2¹⁹. The flexibility claim is conditional on which of these two models you compare
against.

---

## Architecture 4 — PLUM's INNER IOP = STIR (kept distinct from the outer prover)

`src/signatures/plum/` + the Fp192 R1CS gadgets in `src/primitives/r1cs/`. **STIR is
PLUM's OWN inner signature low-degree-test IOP — NOT the outer prover.** The outer
prover is a zkVM (Arch 1/2) or Aurora (Arch 3).

| Component | Field | Role | file:line | Tag |
|---|---|---|---|---|
| Fp192 field | 199-bit prime `p = 2⁶⁴·p₀+1` | base field, 2-adicity 64 | `src/primitives/field/p192.rs:88-95` (`MODULUS_LIMBS`), substitution caveat `:9-44` | VERIFIED |
| Griffin permutation | Fp192 | Merkle-commit hash; width 4, capacity 2, rate 2 | `src/primitives/hash/griffin_p192.rs:42-48`; rounds NB_ROUNDS=14 (per SP1 `air.rs:33`) | VERIFIED |
| STIR LDT IOP | Fp192 | folded low-degree test (η=4 per CLAUDE.md), STIR not FRI | `src/signatures/plum/stir.rs`, `stir_poly.rs` | INFERRED structure — read stir.rs round/fold logic |
| Sumcheck | Fp192 | virtual-oracle / rate sumcheck | `src/signatures/plum/sumcheck.rs` | INFERRED — read sumcheck.rs |
| Verify | Fp192 | the relation being proven in the outer prover | `src/signatures/plum/verify.rs` | INFERRED — read verify.rs control flow |
| t-th power-residue PRF | Fp192, t=256 | `a^((p-1)/t) mod p` symbol checks | `src/primitives/prf/power_residue.rs`, `family.rs`; `p192.rs:105 T_RESIDUE=256` | VERIFIED constant; INFERRED exponent path — read power_residue.rs |

**In-circuit STIR-verifier gadgets — IMPORTANT FILE CORRECTION.** The prompt pointed at
`src/signatures/loquat/r1cs_circuit.rs` for the STIR verifier gadgets. That file is the
**Fp127** Loquat circuit (it references `i²=3` over `field_p127.rs` at
`r1cs_circuit.rs:3816,3850`, VERIFIED) — it is the *template/source*, not the active
Fp192 PLUM gadgets. The **active Fp192 in-circuit PLUM.Verify gadget suite** lives in
`src/primitives/r1cs/`:
- `griffin_fp192_gadget.rs` — Griffin permutation as R1CS (structure ported verbatim
  from Loquat; `:1-10`).
- `merkle_fp192_gadget.rs`, `poly_fp192_gadget.rs`, `stir_round_fp192_gadget.rs`,
  `ood_finalpoly_fp192_gadget.rs`, `rate_sumcheck_fp192_gadget.rs`,
  `fs_fp192_gadget.rs`, `sponge_fp192_gadget.rs` — the gadget suite.
- `plum_verify_fp192_gadget.rs` — FINAL ASSEMBLY composing all gadgets in `verify.rs`
  order, designating pk/message/roots as PUBLIC INPUTS via
  `Fp192R1csBuilder::alloc_public_input` (`:1-25`). VERIFIED.

  **Scale caveat (VERIFIED, from the gadget's own header `:7-17`):** a faithful
  in-circuit FS chain re-absorbs the whole growing transcript per challenge (O(n²) —
  the same cost making one software sign+verify ~60 s at λ=80), so the full PLUM-80
  circuit is "millions of constraints and CANNOT be materialised on a personal machine
  within the runaway bound." The assembly stands up ONE circuit exercising every
  component once at a controlled "gate" scale against a real small signature; the
  PLUM-80 total is PROJECTED arithmetically, never built.

**How a change here propagates.** η (folding) and the Griffin round count change the
STIR query/round structure → the gadget constraint counts and the zkVM Griffin
permutation count. The 192-bit prime substitution affects bit-width-sensitive cost
(limb count) but NOT any decimal-value-conditioned security claim (caveat
`p192.rs:9-44`).

---

# Interaction Surface A — Field propagation (192-bit guest → 31-bit STARK)

**The chain.** PLUM runs over a 199-bit prime (`p192.rs:88`). As a zkVM *guest program*,
each `Fp192` operation must be expressed over the zkVM's small base field (KoalaBear
2³¹ on SP1; BabyBear 2³¹ on RISC Zero). Two distinct renderings:

1. **Software/emulated path (the baseline tax, Cell 1).** `Fp192` is `num_bigint::BigUint`
   internally (`p192.rs:54-62`), so each `mul`/`add` becomes many rv32im instructions
   over the 31-bit field. `add`/`sub` stay fully emulated on both substrates
   (`p192.rs:370-391`, VERIFIED). The module doc states Phase 1.5 will swap to explicit
   4×u64 limb + Barrett/Montgomery to make the limb cost realistic (`p192.rs:58-62`).

2. **Precompiled modmul path.** `Fp192::mul` routes to a syscall: RISC Zero
   `sys_bigint(OP_MULTIPLY)` over a 256-bit slot (`p192.rs:463`, 199-bit zero-padded to
   `[u32;8]`); SP1 `syscall_uint256_mulmod` (`p192.rs:411-443`). VERIFIED.

3. **In-AIR rendering (SP1 Griffin chip — the dedicated precompile).** Inside the
   Griffin-Fp192 chip, each `Fp192` operand is a `Limbs<T, U32>` = **32 u8 limbs**
   (256-bit slot; the 199-bit modulus's top 7 bytes are zero — `curves/src/fp192.rs:27-32,
   100-101`, VERIFIED). One modular multiply is a `FieldOpCols<Fp192FieldParams>`
   enforcing the schoolbook identity `a·b − carry·modulus − result == 0` over the base
   field, with **63 witness limbs** (`2·32−1`) for the carry chain
   (`curves/src/fp192.rs:102-104,138-139`; populate at
   `crates/core/machine/src/operations/field/field_op.rs:42-68`). VERIFIED. Each u8 limb
   is a base-field element range-checked to [0,256) via byte lookups.

**Why Griffin ≈ 91%.** Per CLAUDE.md/PLUM §4.2, ~977 (PLUM-128) / 1052 (PLUM-80 measured)
Griffin permutations per verify, each permutation invoking many `Fp192` mul/pow ops, and
each such op blowing up into 32-limb (256-bit) multi-limb arithmetic with a 63-limb
carry witness. The Griffin chip's own header states the verify spends "~94% of its Fp192
mul cycles and ~100% of its verify wall clock in Merkle hash compressions (Griffin
permutations)" (`griffin_fp192/mod.rs` doc, VERIFIED). The blow-up factor is the limb
count (32) times the carry witness, per permutation, times ~1000 permutations.

**How a change here propagates.** Base-field swap → re-parameterizes the witness-limb
budget per modmul, not the 32 value-limb count (set by the 256-bit slot). Shrinking the
slot to a true 199-bit (25-byte) representation would cut both, but the curves crate
deliberately pads to 256 for "limb compatibility with SP1's U256Field"
(`curves/src/fp192.rs:27-32`).

---

# Interaction Surface B — Precompile ↔ lookup binding (T1) and its failure mode (T2)

This is the binding between the Griffin-Fp192 precompile AIR and the main rv32im
execution trace, on **SP1** (the only substrate with a dedicated Griffin chip).

**The guest emits the syscall.** `plum_griffin_permutation` packs the 4-lane state into
`[u64;16]` (lane i at words [4i,4i+4), little-endian limbs) and calls
`syscall_griffin_fp192_permute(&mut state_words)` when built
`target_os="zkvm", feature="sp1", not(sp1-no-griffin-syscall)`
(`src/primitives/hash/griffin_p192.rs:183-199`, VERIFIED). The host/opt-out fallback runs
the native 14-round permutation (`:217-230`).

**T1 — the three logup bindings that make the chip sound** (all in
`crates/core/machine/src/syscall/precompiles/griffin_fp192/controller.rs`, VERIFIED):

1. **Memory binding** (`:243-250`) — `eval_memory_access_slice_write` ties the 16-word
   state range to historical memory: `memory[i].prev_value` must match the actual memory
   at `addr[i]` (the input the AIR sees) and `memory[i].value` equals the claimed output.
   Single-shot read+write at the same `clk` (Poseidon2-style, vs keccak's split R/W),
   permitted because the executor handler emits paired `MemoryWriteRecords` carrying both
   pre- and post-permutation state (`:232-242`).
2. **Syscall reception** (`:258-267`) — `receive_syscall` for
   `SyscallCode::GRIFFIN_FP192_PERMUTE`, balancing the *send* from the rv32im CPU chip's
   ECALL handling. Comment `:255-257`: "Without this, the executor could claim Griffin
   syscalls that no CPU instruction ever issued — multiplicity mismatch."
3. **Cross-chip lookup** (`:304-326`) — controller (1 row/syscall) *sends* the initial
   state to the per-round chip (received on `is_first_round`) and *receives* the final
   state back (sent on `is_last_round`, direction marker = NB_ROUNDS=14), keyed by
   `InteractionKind::GriffinFp192` (variant 22, payload width 70 = 6 plumbing + 64 state
   u16 limbs; `crates/hypercube/src/lookup/interaction.rs:81-92,142`, VERIFIED).

These interactions are accumulated symbolically into each AIR via `InteractionBuilder`'s
`send`/`receive` (`crates/hypercube/src/lookup/builder.rs:83,92`) and discharged by
LogUp-GKR at `shard.rs:698`. VERIFIED.

**Inside the per-round AIR (the actual constraints — stage-3 COMPLETE).**
`air.rs:3` header: "Phase 3d-stage-3 COMPLETE (2026-05-20)." The S-box/MDS/RC constraints
ARE present as `FieldOpCols<Fp192FieldParams>` (VERIFIED):
- forward S-box (lane 1) = cube via `sbox1_sq` then `sbox1_cube` (`air.rs:164-177`);
- inverse S-box (lane 0) via the witness-and-verify-cube trick — the AIR cannot raise to
  the 199-bit `d_inv` exponent, so it commits the claimed post-S-box value and verifies
  its cube equals the input, which uniquely determines it (`air.rs:251-269`, VERIFIED);
- quadratic lanes 2/3 (`l_sq_*`, `quad_mul_*`, `alpha_l_*`), MDS circulant `mds_out`
  (`air.rs:189-199`), round-constant add `rc_add` with a `< p` canonicality range check
  `rc_add_range_check` (`air.rs:216-302`). VERIFIED.

  **Stale-comment flag:** `griffin_fp192/mod.rs` still calls the chip a "Phase 3b
  skeleton" with constraints "deferred to Phase 3d." That comment is OUT OF DATE — `air.rs`
  (committed 2026-05-20, one day after mod.rs) supersedes it. Resolved via submodule
  `git log`. Do not cite mod.rs's "skeleton" line as current status.

**T2 — failure mode if the binding is wrong.** If the per-round chip's constraints did
NOT actually compute Griffin (the T2 risk the thesis names), the logup multiplicities
would still balance — the cross-table lookup only proves "the controller's claimed output
equals what the per-round chip emitted," not "the per-round chip computed the right
function." Soundness of the precompile thus rests on (a) the in-AIR S-box/MDS/RC
constraints matching the reference row-for-row (the `equivalence_tests/` cross-codebase
test, `platforms/zkvms/sp1/equivalence_tests/tests/griffin_fp192_equivalence.rs`, and the
`fault_injection.rs` negative tests), and (b) the memory-binding + multiplicity checks
above. If memory binding were dropped, the chip could read/write arbitrary state (T2-mem);
if `receive_syscall` were dropped, phantom permutations could be injected (T2-mult). Both
are present (VERIFIED), so the live failure mode is reduced to "do the algebraic
constraints faithfully encode Griffin" — gated by the equivalence + fault-injection tests,
not yet by a written end-to-end soundness proof.

**How a change here propagates.** Adding a round, changing the MDS, or changing the limb
packing requires synchronized edits in three places: the software permutation
(`griffin_p192.rs`), the executor compute (`crates/core/executor/src/griffin_fp192_compute.rs`),
and the AIR (`air.rs`) — the equivalence test is what catches desync.

---

# Interaction Surface C — VEIL masking ↔ multi-shard prover (the structural collision)

**The guard (verbatim).** `slop/crates/veil/src/zk/inner/prover.rs`, fn
`generate_pcs_proofs`, lines 586–599 (VERIFIED; the thesis cited 586-596 — the panic body
runs to 597, brace at 599):

```rust
586  // Check for duplicate commitment indices — multiple eval claims on the
587  // same commitment would leak information and break zero-knowledge.
588  let mut seen = std::collections::HashSet::new();
589  for claim in &eval_claims {
590      for idx in &claim.commitment_indices {
591          if !seen.insert(*idx) {
592              panic!(
593                  "Multiple eval claims on the same PCS commitment (index {}). \
594                   This breaks zero-knowledge but not soundness.",
595                  idx.index(),
596              );
597          }
598      }
599  }
```

Function doc (`:573-574`): "One proof is generated per claim. Panics if multiple claims
exist for the same commitment, as this breaks zero-knowledge." The test
`slop/crates/veil/tests/zk.rs:228` asserts `#[should_panic(expected = "Multiple eval
claims on the same PCS commitment")]`. VERIFIED.

**The structural collision.** A `PcsMultiEvalClaim` carries
`commitment_indices: Vec<MleCommitmentIndex>` (`veil/src/zk/inner/transcript.rs:432`,
VERIFIED) — claims are inherently multi-commitment/multi-point. The SP1 shard prover opens
**the same trace commitment at multiple evaluation points**: the main commitment is opened
both for the zerocheck point and across the jagged round structure (`shard.rs:771` feeds
`Rounds<Evaluations>` over preprocessed+main commitments; `prove_trusted_evaluations`
samples additional `z_col` points, `jagged/prover.rs:177-181`). VEIL masks each opening
with one fresh mask per (commitment, point); two claims hitting the same commitment index
would reuse/leak the mask, so VEIL forbids it by panicking. Real SP1 workloads produce
multiple openings per commitment, so wiring VEIL into the live prover would trip this
guard. (Mechanism VERIFIED from guard + claim type + opening call; "real workloads always
trip it" is INFERRED from the opening structure — cannot be observed because, next point.)

**Why it is moot today.** VEIL is **not wired into the prover at all** — only a workspace
path entry (`submodules/sp1/Cargo.toml:202`) and its own manifest; no crate depends on it
(VERIFIED). So `generate_pcs_proofs` is never called in production; the guard cannot fire.
The thesis's "ZK via `.compressed().groth16()`" is the gnark BN254 wrap (Surface-1
component 6), entirely separate from slop-veil. The thesis's PQ-ZK-via-masked-FRI angle is
therefore a *what-if* about VEIL, not a live code path — and the collision above is the
structural reason VEIL is hard to wire without reworking the multi-point opening contract.

**How a change here propagates.** To make VEIL usable you would have to batch every
opening of a commitment into a single multi-point eval claim (so each commitment index
appears once) before masking — i.e., change the prover's opening discipline, not just
flip a feature flag.

---

# Interaction Surface D — Same relation, different substrate (Aurora-Fp127 vs zkVM-KoalaBear)

**What is the same.** Both prove a Verify-style relation reduced to constraints. Both end
in a Merkle/FRI-style argument made non-interactive by Fiat-Shamir (libiop BCS; SP1
Basefold + Poseidon2 transcript).

**What is NOT comparable (the honest caveats):**
1. **Different relation instance.** The zkVM proves **PLUM-Griffin over Fp192**
   (`plum_verify_griffin.rs`); the Aurora measurement proves **Loquat-BDEC over Fp127**
   (`emit_aurora_r1cs.rs` + `fp127_aurora_runner.cpp`). PLUM-in-Aurora-Fp192 is NOT
   runnable (fp127-only harness; `docs/r_static_finding_20260605.md`). So Cell 4 is a
   *proxy*, conflating the scheme change (PLUM↔Loquat), the field change (Fp192↔Fp127),
   the hash change (Griffin↔Loquat's hash), and the inner-IOP change (STIR↔FRI). CLAUDE.md
   already flags this.
2. **Different native field, different cost model.** Aurora is RS-encoded directly over
   its 127-bit field (no multi-limb tax — the relation field *is* the proving field). The
   zkVM emulates Fp192 over a 31-bit field (the 32-limb tax of Surface A). The substrate
   comparison therefore measures "native-field SNARK vs emulated-field zkVM," which is
   exactly the field-mismatch the thesis studies — but it is NOT an apples-to-apples
   same-relation timing.
3. **Different proof system class.** Aurora = transparent non-preprocessing R1CS SNARK
   (R_static ≈ 0.3 s, recompile-cheap); the zkVM = STARK with a recursion/Groth16 wrap for
   ZK. Fractal adds preprocessing (indexer; R_static 0.86–18.5 s synth, OOM at 2¹⁹). The
   "flexibility" comparison is only meaningful once you fix which model (preprocessing or
   not) you compare against — per `docs/r_static_finding_20260605.md`.

**What IS comparable.** Same-scheme Loquat substrate gap has been measured: Aurora 3.76 vs
zkVM 55.93 min (~15×) — see memory `thesis-loquat-substrate-and-audit-2026-06`. That holds
the scheme fixed and varies only the substrate, which is the clean axis.

**How a change here propagates.** Any claim conditioned on "same relation" must name which
of the four conflated axes (scheme/field/hash/inner-IOP) it holds fixed; the only clean
same-relation number in the repo is the Loquat-on-both-substrates one.

---

# Deepest unread spots (ranked by confidence gain)

1. **The `risc0-zkp` / `risc0-circuit-rv32im` crate internals** (BabyBear modulus, rv32im
   AIR, DEEP-ALI, FRI, and the `sys_bigint` Zirgen bigint AIR). NONE of RISC Zero's
   proving core or precompile-constraint logic is vendored — everything in Architecture 2
   below the syscall boundary is INFERRED from `Cargo.lock`. Reading these would convert
   the entire RISC Zero substrate from inferred to verified. (Fetch the crate sources for
   `risc0-zkp 3.0.4`, `risc0-circuit-rv32im 4.0.4`.)

2. **libiop `.tcc` bodies** — `aurora_snark.tcc`, `aurora_iop.tcc`, `bcs_prover.tcc`,
   `fractal_snark.tcc`. The component roles are structurally clear but the RS-encoding
   degree, the univariate-sumcheck rounds, the Merkle-root-per-round Fiat-Shamir
   discharge, and the exact Fp127 field typedef (is it 2¹²⁷−1 Mersenne or a generic
   127-bit prime; is F_{p²} used in the *outer* SNARK or only inside Loquat) were not read
   line-by-line.

3. **PLUM's `stir.rs` / `verify.rs` / `sumcheck.rs` internal logic.** Confirmed the files
   and field; did NOT read the STIR fold/round structure, how it differs from FRI in code,
   or whether the software `verify.rs` actually runs the proximity test (the PLUM agent
   flagged a possible deferred-proximity-test soundness caveat — worth a direct read).

4. **SP1 controller stage-ordering + recursion reduce-tree** —
   `crates/prover/src/worker/controller/{mod,global,core,compress}.rs`. The async
   message-passing core→compress→shrink→wrap dispatch and the shard-combination arity
   were INFERRED from types, not read end-to-end.

5. **`impl IopCtx for SP1GlobalContext`** — verified `SP1Field = KoalaBear` and that
   Basefold/Merkle are KoalaBear-parameterized, but did not read the single impl pinning
   `type F`/`type EF`/`type Challenger` for the core config.

6. **Whether the `MleCommitmentIndex` repeat truly occurs at runtime** (Surface C) — argued
   from the opening structure; cannot be observed because VEIL is unreachable. Would
   require wiring VEIL into a shard prove to confirm the guard would actually trip.
