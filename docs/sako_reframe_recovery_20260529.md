# Sako reframe — recovery doc (2026-05-29 morning)

Written 01:50 JST after overnight benchmark suite finished. Read first thing in
peak window. **Do not act on this at 01:50** — it is here so the morning has a
clean starting point.

---

## 0. TL;DR

- Sako reframed the thesis: **PLUM instantiated into BDEC, running in {RISC0,
  SP1}, motivated by escaping the rigidity crisis of static circuits via
  zkVM**.
- I previously claimed BDEC was not in any zkVM. **That was wrong.** BDEC has
  an integrated RISC0 host (`platforms/zkvms/risc0/host/src/pp2_showver.rs`,
  ~813 lines) that runs BDEC showcre operations. It currently uses **Loquat**
  as the underlying signature, not PLUM.
- The actual integration gap is not "BDEC vs no BDEC" — it is
  **PLUM-with-precompiles × BDEC-RISC0-host**: the precompile work and the
  BDEC zkVM work were done on different tracks and have not been joined.
- Tonight's overnight suite produced three findings (one unexpected) and one
  toolchain failure. **Dilithium baseline succinct prove OOMed**, which I had
  framed as ZK-wrap OOM — wrong, it is a pure STARK prove OOM. Stronger
  finding than what I told you at 01:30.

---

## 1. Where the code actually lives (correcting my earlier mistake)

| Component | File / path | Status |
|---|---|---|
| BDEC module (issuance, showcre, revocation) | `src/anoncreds/bdec/mod.rs` (91 KB) | exists; uses **Aurora** (in-SNARK) for credential issuance proofs |
| BDEC pp2 showcre on RISC0 | `platforms/zkvms/risc0/host/src/pp2_showver.rs` | exists; uses **Loquat** as the signature |
| BDEC showcre classical benchmark | `src/bin/bdec_showcre_benchmark.rs` | exists; built binary in `target/release/` |
| BDEC pp3 benchmark | `src/bin/bdec_pp3_benchmark.rs` | exists |
| BDEC demos | `src/bin/bdec_demo.rs`, `bdec_link_demo.rs`, `bdec_merkle_revocation_demo.rs` | exist |
| BDEC static-circuit Noir version | `platforms/compilers/noir/bdec_showver/` | exists |
| PLUM verify guest + host on SP1 | `platforms/zkvms/sp1/program*/` + `platforms/zkvms/sp1/script/src/bin/plum_host.rs` | exists; **NO BDEC integration** |
| PLUM precompile suite (Griffin Fp192, etc.) | inside SP1 program builds | exists; Cell 2 = 32.5 min measured |
| RISC0 host wiring for PLUM-with-precompile | nowhere | **the actual integration gap** |
| SP1 host wiring for PLUM-in-BDEC | nowhere | **the other half of the gap** |

## 2. Tonight's suite — actual outcomes

Suite started 01:13:10 JST, ended 01:40:42 JST. Read
`/tmp/bench_suite_20260528/SUMMARY.txt` for the raw log; copy to project before
next restart since `/tmp` is wiped on reboot.

| Job | Result | Peak RSS | Interpretation |
|---|---|---|---|
| 01 sphincs_prove | ✅ rc=0, 170s, prove_ms=10228 | 11.26 GB | SLH-DSA proxy verify prove fits cleanly. **Anchors no claim** for any audience pitch I named. |
| 02 dilithium_prove | ❌ rc=1, jetsam SIGKILL after 249s | 12.59 GB resident, **82.7 GB peak memory footprint** | **ML-DSA proxy verify baseline STARK prove exceeds 24 GB.** `bench_pqc.rs:313` confirmed pure `client.prove(...).run()`, not ZK-wrap. This is a **stronger** finding than ZK-wrap OOM — even baseline succinct proof of a standardized PQ verify doesn't fit on 24 GB. |
| 03 plonk_zkwrap_quartered | ❌ rc=1, OOM after 1194s (~20min) | 19.98 GB resident, 17.80 GB sampler peak | PLUM PLONK ZK-wrap died at ~20 GB on quartered config. Below 24 GB nominal ceiling but jetsam killed it under pressure. **The expected and headline finding for the personal-PC angle.** |
| 04 loquat_lambda128_prove | ❌ rc=101, panic in 10s | 700 MB (no real work done) | **NOT a science result.** SP1 toolchain build error: `error loading target specification: could not find specification for target "riscv64im-succinct-zkvm-elf"`. The bench_pqc binary's Loquat build path doesn't see the SP1 succinct rustc. Daytime build-system debugging required. |

**Saved logs**: `/tmp/bench_suite_20260528/` — copy to `docs/measurements/` or
similar before next reboot.

## 3. Sako's reframe restated operationally

What she said vs what I think she means:

| Sako's words | Operational reading |
|---|---|
| "I thought you ran specific measurements that can convince people" | Each measurement should anchor a named load-bearing claim. Most of your current numbers anchor "precompile reduces field-mismatch tax" — they do NOT anchor "PLUM-in-BDEC works in zkVM." |
| "What am I proving? What am I running?" | Name the proposition first. Justify the measurement against it. Measurement-as-evidence, not measurement-as-exploration. |
| "Stick to BDEC, fix one thing: PLUM instantiated into BDEC, in RISC0 and SP1" | Scope is fixed: BDEC issuance/showcre with PLUM as the signature, measured cross-substrate. Not three audiences — one story with a specific scope. |
| "X× speedup against what?" | The comparator is downstream of the proposition. Without naming the proposition you cannot defend the comparator. |
| "Solve rigidity crisis of static circuits by moving to zkVM" | The load-bearing claim is **escape rigidity**, not "fast proofs." Speedup is one consequence; programmability and updatability are the actual values being defended. |

## 4. The actual integration gap

Both halves of the gap exist on master right now:

```
PLUM precompile suite (SP1, Griffin Fp192, etc.) — Cell 2 measures it
                          +
BDEC RISC0 host (pp2_showver.rs, uses Loquat)
                          =
PLUM-in-BDEC × {RISC0, SP1} — Sako's structured scope
```

The integration work, broken down:

1. **Swap Loquat → PLUM inside `pp2_showver.rs`.** The BDEC RISC0 host
   currently invokes `bdec_setup_zk` → uses Loquat. The BDEC module
   (`src/anoncreds/bdec/mod.rs`) uses `aurora_prove` (in-SNARK Aurora) for
   credential issuance. To make this PLUM-in-BDEC, the signature primitive
   under BDEC needs to be switched. Estimated cost: depends on how decoupled
   BDEC is from Loquat. Read `src/anoncreds/bdec/mod.rs` first.

2. **Port the PLUM precompile suite from SP1 to RISC0** (or run both). The
   precompile work is currently SP1 application-defined precompiles. RISC0
   uses Zirgen bigint MLIR for the same role. Same algorithm, different
   substrate. Estimated cost: substantial — the Griffin Fp192 precompile
   logic transfers, but the SP1 syscall ABI ≠ RISC0 syscall ABI.

3. **Build the SP1 BDEC host.** SP1 currently has `plum_host.rs` for
   PLUM-verify-in-isolation. No BDEC host on SP1. Would need to mirror the
   RISC0 pp2_showver.rs structure but for SP1.

4. **Re-measure Cells 1/2/3 with PLUM-in-BDEC as the circuit instead of
   PLUM-verify-in-isolation.**

Order matters. Option (1) alone (Loquat→PLUM in RISC0 BDEC host, without the
precompile suite) gives you Cell 1 of the BDEC scope on RISC0 — a baseline
measurement that says "PLUM-in-BDEC in RISC0 without precompile". That
would already be more relevant to Sako than tonight's data.

## 5. Three options for peak-window decision

Restated cleanly given the corrected picture:

| Option | What it commits to | New engineering | What it gives you for the thesis |
|---|---|---|---|
| **A. Loquat→PLUM in RISC0 BDEC host only** | Use existing BDEC RISC0 host, swap signature primitive, no precompile work yet | ~days, depends on BDEC↔Loquat coupling | One Cell on Sako's scope: PLUM-in-BDEC-RISC0 baseline. Comparable to the existing Loquat-in-BDEC-RISC0 numbers. Doesn't yet show the precompile fix. |
| **B. A + port precompile suite to RISC0** | Above + Griffin Fp192 precompile in RISC0 (Zirgen) | weeks | Full Cell 1/2 picture on Sako's scope: PLUM-in-BDEC-RISC0 with vs without precompile. |
| **C. A + build SP1 BDEC host + cross-substrate** | Above + SP1 BDEC host, run on both substrates | weeks | The full {RISC0, SP1} cross-substrate picture Sako structured. |

**Option A is the smallest concrete step that moves toward Sako's structure.**
Tonight's data is silent on it. Tomorrow morning's task is to confirm Option
A is the next move and scope it concretely.

## 6. Immediate items for morning

In peak-window order:

1. **Read `src/anoncreds/bdec/mod.rs`** to confirm how the signature is
   abstracted. If it's parameterized over a signature trait, Loquat→PLUM
   is a small change. If it's hard-coded to Loquat types, it's larger.
2. **Read `platforms/zkvms/risc0/host/src/pp2_showver.rs`** to see what the
   actual measurement target would look like with PLUM in place of Loquat.
3. **Confirm Option A as the next move with Sako before doing more work.**
   The most likely failure mode is investing days of engineering and
   having her say "that's not what I meant." Send her the scoped Option A
   plan first.
4. **Resolve the SP1 toolchain issue blocking Loquat λ=128 bench_pqc**
   only if cross-substrate Loquat numbers will be cited in the paper. If
   not, drop.
5. **Save tonight's logs out of `/tmp`** before any future reboot:
   `cp -r /tmp/bench_suite_20260528 docs/measurements/`.

## 7. What this changes about tonight's framing

I told you at 01:30 the answer to Sako's reframe was "pick an audience among
three." That was the engineer-mode-evasion framing, exactly what Sako was
flagging.

The actual answer is: **the scope is already decided** (PLUM-in-BDEC ×
{RISC0, SP1}). The question is which integration step you commit to first,
and whether to validate that step with Sako before investing the engineering.

The audience-mapping conversation was useful for surfacing what each story
*would* require, but it framed the choice as a strategic pick. Sako's
framing makes it a sequencing question instead.

---

*This doc is recovery material, not a plan. Sleep first. Re-read at
10:00–14:00 JST.*
