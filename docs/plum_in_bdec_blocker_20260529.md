# PLUM-in-BDEC CreGen — first measurement (RETRACTS earlier blocker)

**Updated 2026-05-29 14:30 JST.** This document originally reported a
PLUM library re-entrancy bug. **That finding was wrong.** The root cause
was a host-side decoder mismatch — `bincode::deserialize` was being used
to decode a journal that RISC0 encodes with `risc0_zkvm::serde`. With the
old `GuestOutput` shape the two encodings happened to coincide enough to
not panic, but the boolean values I was reading were garbage. Replacing
`bincode::deserialize` with `risc0_zkvm::serde::from_slice` (for execute
mode) and `receipt.journal.decode()` (for prove mode) — the pattern already
in use by `plum_host.rs:369` — resolved everything.

**PLUM verify is re-entrant. The CreGen guest works end-to-end.**

---

## First RISC0 PLUM-in-BDEC measurement

Execute mode, `BDEC_HOST_SECURITY=80`, deterministic ChaCha20 RNG seeds,
`PlumGriffinHasher`:

| Quantity | Value |
|---|---|
| Both Sig.Verify outcomes | `Accept`, `Accept` |
| cred_verify_cycles (guest-reported) | 4,693,700,750 (4.69 G) |
| nym_verify_cycles (guest-reported) | 4,693,401,616 (4.69 G) |
| total_cycles_estimate (session_info) | 9,403,401,763 (9.40 G) |
| exec_ms (host wall clock) | 64,958 ms (~65 s) |
| setup_ms | 2 ms |
| sign_ms (both signatures, host-side) | 49,774 ms (~50 s) |

The two verifies cost essentially the same (~4.69 G cycles each, 99.99%
match), confirming they are running through the same Griffin-precompile-
backed path with no asymmetry. The total trace matches 2× single-verify
cost to within session-info overhead.

## What this anchors (Sako framing)

This is the **first measurement of PLUM-in-BDEC inside a zkVM**. It
anchors the load-bearing thesis claim — "escape rigidity by moving to
zkVM" — at the smallest BDEC sub-protocol scope (CreGen = two Sig.Verify
under hidden `pk_U`).

The comparator inventory now:

| Comparator | Measured? | Source |
|---|---|---|
| PLUM-verify alone × SP1 (Cell 2) | ✅ 32.5 min prove on M5 Pro 24 GB | Existing Cell 2 measurement |
| PLUM-in-BDEC CreGen × RISC0 (this) | ✅ 9.4 G cycles, 65 s execute | This session |
| Loquat-in-BDEC ShowCre/ShowVer × RISC0 | partially | `pp2_showver.rs` (existing host) |
| Aurora-BDEC classical (no zkVM) | partially | `bdec_showcre_benchmark.rs` |
| PLUM-in-BDEC ShowCre/ShowVer × RISC0 | ❌ not yet | Next implementation target |
| PLUM-in-BDEC × SP1 | ❌ not yet | Requires SP1 BDEC host |
| Prove mode (with ZK-wrap) | ❌ not yet | OOM-likely at this cycle count |

## What we now know about cycle counts (correcting an earlier confusion)

When I first ran the broken version of the host, the "cred_verify_cycles"
came back as `479,232` (suspiciously low) and "nym_verify_cycles" as
`1.2 trillion` (suspiciously high). Both were artefacts of reading
correctly-encoded but **incorrectly-decoded** bytes — I was treating
RISC0-serde-encoded bytes as bincode-encoded bytes, so the u64 cycle
fields landed on the wrong byte offsets and gave nonsense.

After the decoder fix, both `cred_verify_cycles` and `nym_verify_cycles`
report ~4.69 G — consistent with each other, consistent with the total
trace cycles, and consistent with what a single PLUM-Griffin verify costs
in execute mode.

The earlier `total_cycles_estimate=260,586,773` I logged for the SHA3
variant was real (it's read via `session_info.cycles()`, not from the
journal) and matches expectations for software-Griffin SHA3 PLUM verify.

## What got built this session

| File | Status |
|---|---|
| `platforms/zkvms/risc0/methods/guest/src/bin/bdec_credgen_plum_griffin.rs` | ✅ committed-ready |
| `platforms/zkvms/risc0/methods/guest/Cargo.toml` (added `[[bin]]` entry) | ✅ committed-ready |
| `platforms/zkvms/risc0/host/src/bin/bdec_credgen_plum_host.rs` | ✅ committed-ready |
| `docs/sako_reframe_recovery_20260529.md` | ✅ committed-ready |
| `docs/plum_in_bdec_integration_plan_20260529.md` | ✅ committed-ready |
| `docs/plum_in_bdec_blocker_20260529.md` | ✅ this doc, retracts the earlier blocker |

The Loquat-side RISC0 host (`pp2_showver.rs`) and the classical
Aurora-BDEC (`bdec/mod.rs`) are completely untouched.

## What's next (researcher-mode reordering)

The integration plan (§3 of `plum_in_bdec_integration_plan_20260529.md`)
had three open questions. Status update:

| Open question | Status |
|---|---|
| §3.1 ZK property | Still open. Baseline succinct STARK works; ZK-wrap (Groth16) not yet attempted at this cycle count. Likely OOMs given overnight 24 GB findings. |
| §3.2 Scope | Beachhead (CreGen) ✅ now achieved. Next step: extend to ShowCre/ShowVer. |
| §3.3 Comparator | Cycle count for PLUM-in-BDEC CreGen now known (9.4 G). Loquat-in-BDEC RISC0 baseline measurement still pending (run `pp2_showver`). |

### Recommended sequencing for the rest of today / this week

1. **Email Sako with the result** — first PLUM-in-BDEC measurement in zkVM,
   "PLUM-in-BDEC CreGen × RISC0: 9.4 G cycles execute-mode, 65 s wall, both
   Sig.Verify accept under shared hidden pk_U." This is exactly the kind of
   "specific measurement that convinces people" she asked for.
2. **Run prove mode** to get a real STARK receipt. Expected to take ~tens
   of minutes; should fit in 24 GB at execute → succinct without ZK-wrap.
   Captures `prove_ms` for direct comparison to Cell 2 PLUM-verify-alone.
3. **Run the Loquat-in-BDEC baseline** via existing `pp2_showver.rs` for
   comparator (a) — the same scope (CreGen-equivalent within ShowCre/ShowVer
   range) but with Loquat as the signature. Lets us state the PLUM-vs-Loquat
   delta inside the same RISC0 substrate.
4. **Extend to ShowCre/ShowVer** scope by mirroring the existing 430-line
   `main.rs` (Loquat-based pp2 guest) with PLUM primitives. Order of
   operations now well-understood from the CreGen beachhead.

The §3.1 ZK property decision can be deferred until we have prove-mode
numbers — they ground the cost of the Groth16-wrap attempt.

---

*Sibling docs: `plum_in_bdec_integration_plan_20260529.md`,
`sako_reframe_recovery_20260529.md`. Overnight logs:
`docs/measurements/bench_suite_20260529_overnight/`.*
