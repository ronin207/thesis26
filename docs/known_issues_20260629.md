# Known engineering issues — tracked 2026-06-29

Issues found during the measurement-provenance cleanup (Tier 3). These do NOT
affect the thesis's logged numbers (which were measured at the faithful config),
but are live in the code and tracked here for resolution.

## I-1 — Quadratic Fiat–Shamir re-absorb in the Griffin-FS path  [open]

**Where:** `src/primitives/r1cs/fs_fp192_gadget.rs:169-182` (`squeeze_once` /
`plum_griffin_sponge`), reached via `src/signatures/plum/transcript.rs:107,149,200`
when `H::USE_GRIFFIN_FS == true`.

**What:** the Griffin-FS challenge derivation rebuilds the sponge from a fresh
zero state over the *entire* running absorbed-field log on every challenge:
`inputs = absorbed.clone() ++ [tag, sc, c]; plum_griffin_sponge(params, inputs, 1)`.
This is **O(#challenges × |transcript|)** — quadratic in the number of FS challenges.

**Impact:** for PLUM-80 verify it inflates the Griffin-permutation count from the
faithful **~1,052** (Merkle-dominated, SHAKE-FS) to **6,575** when Griffin-FS is
active. PLUM Algorithm 6 (p.122 line 3) mandates an *incremental* hash chain
(running state, one expansion per round), which a correct implementation would
realize in **~99** extra perms (→ ~1,150 total), not ~5,500.

**Introduced:** commit `ff77120` (2026-06-23), which set
`PlumGriffinHasher::USE_GRIFFIN_FS = true` for the Stage 4c-4 circuit gate. The
same const governed the zkVM runtime transcript, silently re-routing it.

**Current state:** dormant for the runtime measurement after the Tier-1 decouple
(commit `b692f0b`): the guest/host now use `PlumGriffinShakeFsHasher`
(`USE_GRIFFIN_FS = false`, SHAKE-FS). `PlumGriffinHasher` (Griffin-FS, quadratic)
remains the path the Stage 4c-4 circuit gate exercises.

**Fix when Griffin-FS is wanted on a hot path:** make the sponge incremental —
carry the running sponge state across challenges (one expansion per round) instead
of re-absorbing the full log. Re-verify the perm count lands at ~1,150, not 6,575.

## I-2 — Stale doc-comment on plum_verify  [RESOLVED 2026-06-29, comment corrected]

**Where:** `src/signatures/plum/verify.rs:148-165`.

**Resolution:** signatures-sot traced `plum_verify` line-by-line against PLUM
Algorithm 6 (paper p.122). The function-level comment ("STIR-fold check and Merkle
openings are not currently performed") was **STALE** — it described an earlier
residuosity-only version. The code performs the **full** Algorithm 6: FS replay
(186-225), leaf recompute (271-495), Merkle openings (372-721, live on the accept
path), STIR fold-consistency (587-616), low-degree/sumcheck (502-575),
final-polynomial (648-773), residuosity (227-253); single `Accept` at :777, and
every check has a tamper test forcing the reject. The 1,052 Griffin perms ARE the
Merkle/STIR openings. **No soundness gap inside `plum_verify`; Cells 1/2/3 measure a
complete, faithful PLUM verifier.** The stale comment was corrected this session. The
in-circuit Griffin-AIR gadget-soundness assumption (asm:air) is a separate,
correctly-disclosed open premise, unaffected. (Scope: the instrumented
`plum_verify_phased` at verify.rs:870 was not separately traced; check it if a RISC0
counter relies on that variant.)
