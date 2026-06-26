# SP1 BDEC execute-mode measurement — Griffin precompile on the BDEC relations

- **Date:** 2026-06-02
- **Hardware:** MacBook Pro M5 Pro (18-core CPU, 24 GB)
- **zkVM:** SP1 v6.2.1 (forked, additive Griffin-Fp192 chip), toolchain `succinct` (`rustc 1.93.0-dev`)
- **Scheme:** PLUM-80-Griffin
- **Mode:** **execute** — RISC-V instruction count + syscall counts from SP1's
  `ExecutionReport`. Machine-independent. **NOT prove time.**

## What this adds to the evaluation

The with/without-precompile comparison previously spanned two platforms (RISC0
software-Griffin vs SP1-precompile, and only for a *single* verification) — a
comparison confounded by the platform difference. These runs put **both arms on
SP1, on the actual BDEC relations** (CreGen, ShowCre), with the *only* variable
being the Griffin implementation:

- **syscall arm** — Griffin via the `GRIFFIN_FP192_PERMUTE` precompile.
- **emulated arm** — Griffin in rv32im (`vc-pqc/sp1-no-griffin-syscall`).

`UINT256_MUL` stays on in **both** arms, so the delta isolates the **Griffin**
precompile specifically, not "any precompile."

## Results

| relation | verifs n | syscall cycles | emulated cycles | reduction | griffin perms (syscall) | uint256_mul (emulated) | execute wall (sys / emu) |
|---|---|---|---|---|---|---|---|
| CreGen      | 2 | 242,964,563 | 14,152,091,640 | 58.2× (−98.28%) | 2,104 |  9,740,549 | 3.6 s / 71 s |
| ShowCre k=1 | 3 | 362,637,683 | 20,797,277,508 | 57.3× (−98.26%) | 3,156 | 14,610,448 | 4.9 s / 108 s |
| ShowCre k=2 | 4 | 481,746,640 | 28,238,593,333 | 58.6× (−98.29%) | 4,208 | 19,480,415 | 6.2 s / 149 s |

Both arms accept the honest witness on every run. The emulated arm fires **0**
Griffin syscalls and the syscall arm **>0** (the host asserts both — a broken cfg
gate fails loudly rather than silently mis-measuring). Only the aggregate `bool`
is committed; `pk_U` and all signatures remain private witnesses.

## Findings

1. **The Griffin precompile removes ~98.3% of cycles (~58×), consistently across
   CreGen and ShowCre.** The factor is stable (58.2 / 57.3 / 58.6×) independent of
   relation size — the precompile's benefit does not erode as the relation grows.

2. **Griffin is ~98.3% of the *zkVM cycle* cost** (emulated arm), *higher* than the
   91% R1CS-constraint share PLUM §4.2 reports for the circuit-SNARK. This is the
   measurement CLAUDE.md required ("do not assume the 91% hash share transfers to
   the zkVM cost model — measure"). It does not transfer unchanged; it is larger in
   the cycle model, because software Griffin over a 192-bit prime in rv32im is
   disproportionately expensive per permutation.

3. **The additive cost model holds.** Per signature verification:
   - Griffin permutations: **exactly 1052 / verification** (2104/2 = 3156/3 = 4208/4).
   - syscall cycles: **~1.20×10⁸ / verification** (120.4–121.5 M, spread <0.9%).
   - emulated cycles: **~7.0×10⁹ / verification** (6.93–7.08×10⁹, spread <2%).

   So CreGen ≈ 2× and ShowCre(k) ≈ (k+2)× a single verification: a BDEC relation's
   cost is linear in its signature-verification count, validating the additive
   model used for extrapolation elsewhere.

## Framing / honesty (do not overstate)

- These are **execute-mode cycle counts** (machine-independent), **not prove
  times**. They quantify the precompile's effect on prove feasibility/cost; the
  deployable Groth16 prove still exceeds the 24 GB budget on the M5 (the frontier
  finding) and is not measured here.
- **PLUM-80**, SP1 cycle model — a different parameter set *and* cost model from
  the 91% / 116,285-constraint PLUM-128 R1CS figure. Do not conflate the two.
- This ~58× cycle reduction is a **distinct metric** from the "70× PLUM-standalone
  (precompile on/off)" headline. The per-single-verification cycle reduction here
  is ~58× (7.0×10⁹ / 1.20×10⁸). Reconcile the metrics before citing either number;
  do not present 58× and 70× as the same measurement.

## Cross-check

Single-verification syscall cycles (~1.20×10⁸) are order-consistent with the prior
SP1 single-verify prove of ~32.5 min: ~1.20×10⁸ / 2²⁰ ≈ 115 segments → ~17 s/segment,
a plausible SP1 segment-proving rate.

## Reproduce

PATH must put `~/.cargo/bin` ahead of any Homebrew rust, so `rustc +succinct`
resolves to the SP1 fork (which carries the `riscv64im-succinct-zkvm-elf` target)
rather than `/opt/homebrew/.../rustc` (which does not). Then:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export VC_PQC_SKIP_LIBIOP=1
# build (guests in syscall + emulated arms via build.rs, hosts in release)
cargo build --release --manifest-path platforms/zkvms/sp1/script/Cargo.toml \
  --bin bdec_cregen_host --bin bdec_showcre_host
# measure
cargo run --release --manifest-path platforms/zkvms/sp1/script/Cargo.toml --bin bdec_cregen_host
BDEC_SHOWCRE_K=1 cargo run --release --manifest-path platforms/zkvms/sp1/script/Cargo.toml --bin bdec_showcre_host
BDEC_SHOWCRE_K=2 cargo run --release --manifest-path platforms/zkvms/sp1/script/Cargo.toml --bin bdec_showcre_host
```

Raw logs: `/tmp/sp1_cregen_exec.log`, `/tmp/sp1_showcre_k1.log`, `/tmp/sp1_showcre_k2.log`
(session 2026-06-02).
