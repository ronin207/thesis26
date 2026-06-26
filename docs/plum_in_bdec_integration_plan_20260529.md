# PLUM-in-BDEC integration plan (RISC0 first)

**Status: PROPOSED — awaiting review at 10:00–14:00 JST 2026-05-29.**
Written 02:15 JST after read-only investigation. Companion to
`sako_reframe_recovery_20260529.md`.

This plan is concrete enough to implement, but **not implemented**. The
researcher posture requires conscious authorization for code that touches
witness handling, secret keys, and proof-system substitutions. Approve,
reject, or redirect before I write a line.

---

## 1. Updated picture from the investigation

Significant corrections to my recovery doc:

| Belief before | Actual state |
|---|---|
| "BDEC isn't in any zkVM." | False. `pp2_showver.rs` (RISC0 host, 813 lines) orchestrates BDEC operations and invokes `prover.prove_with_ctx(env, verifier_ctx, ZKVM_RISC0_ELF, prover_opts)`. |
| "Loquat→PLUM is a small swap in bdec/mod.rs." | False. `bdec/mod.rs` is hard-wired to `LoquatSignature`, `LoquatPublicParams`, `loquat_sign/verify`, `build_loquat_r1cs_pk_witness`, and Loquat's `F_{p²}` field. It is **not abstracted over a signature trait.** The Aurora SNARK underneath is also field-parameterized to Loquat. |
| "PLUM verify isn't in RISC0." | False. `platforms/zkvms/risc0/methods/guest/src/bin/plum_verify_griffin.rs` exists — a RISC0 guest that runs `plum_verify` with the Griffin Fp192 precompile. The PLUM-on-RISC0 piece is already written. |

The actual gap, now precise:

```
EXISTS:   RISC0 guest binary that runs ONE plum_verify call (plum_verify_griffin.rs)
EXISTS:   RISC0 host that orchestrates BDEC and invokes the zkVM prover (pp2_showver.rs)
EXISTS:   classical BDEC module with Aurora-based credential proofs (bdec/mod.rs, Loquat-only)
MISSING:  RISC0 guest binary that runs the BDEC CreGen statement
          (two plum_verify calls under hidden pk_U)
MISSING:  pp2_showver wiring to prove that new guest with PLUM-typed inputs
```

This is meaningfully smaller than "swap Loquat→PLUM in bdec/mod.rs."

## 2. Proposed change (RISC0 first, the path Sako structured)

### 2.1 New guest binary

**File**: `platforms/zkvms/risc0/methods/guest/src/bin/bdec_credgen_plum_griffin.rs`

Mirror of `plum_verify_griffin.rs`, but runs **two** `plum_verify` calls under
a shared `pk_U`. Output asserts both verifications passed. Counters aggregated
across both calls.

Sketch (paraphrased, not final):

```rust
use vc_pqc::plum::{
    keygen::PlumPublicKey,
    setup::PlumPublicParams,
    sign::PlumSignature,
    verify::{VerificationOutcome, plum_verify},
    hasher::PlumGriffinHasher,
    // counter atomics same as plum_verify_griffin.rs
};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,             // SECRET WITNESS — see §3.1
    h_u_ta: Vec<u8>,                 // public: attribute hash
    c_u_ta: PlumSignature,           // witness
    ppk_u_ta: Vec<u8>,               // public: pseudonym public bytes
    psk_u_ta: PlumSignature,         // witness
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    sig_ok: bool,
    nym_ok: bool,
    counters: PlumGuestCounters,     // reuse type from plum_verify_griffin.rs
}

fn main() {
    let input: GuestInput = env::read();
    // reset counters (same pattern as plum_verify_griffin.rs)
    let sig_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&input.pp, &input.pk_u, &input.h_u_ta, &input.c_u_ta),
        VerificationOutcome::Valid,
    );
    let nym_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&input.pp, &input.pk_u, &input.ppk_u_ta, &input.psk_u_ta),
        VerificationOutcome::Valid,
    );
    env::commit(&GuestOutput { sig_ok, nym_ok, counters: snapshot() });
}
```

This is the **BDEC CreGen statement** of ProSec 2024: two Sig.Verify under
hidden `pk_U`. With PLUM as the signature, the field-mismatch tax inside
each `plum_verify` is mitigated by the existing Griffin Fp192 precompile.

### 2.2 Methods build wiring

**File**: `platforms/zkvms/risc0/methods/build.rs` (or `Cargo.toml`,
depending on which controls the bin-list)

Register `bdec_credgen_plum_griffin` as a built guest binary. The host
needs to be able to reference `BDEC_CREDGEN_PLUM_GRIFFIN_ELF` and
`BDEC_CREDGEN_PLUM_GRIFFIN_ID`.

**I have not yet read `methods/build.rs` / `methods/Cargo.toml`.** The
exact change shape depends on whether bin auto-discovery is enabled.
Verify before writing.

### 2.3 Host-side change

**File**: `platforms/zkvms/risc0/host/src/pp2_showver.rs`

Currently invokes `ZKVM_RISC0_ELF` (a single ELF, likely the main
Loquat-based guest). The proposed change adds (does not replace) a
parallel code path that:

1. Constructs `GuestInput` with PLUM-typed values
2. Calls `prover.prove_with_ctx(env, verifier_ctx, BDEC_CREDGEN_PLUM_GRIFFIN_ELF, prover_opts)`
3. Records prove time, cycle count, peak RSS

Add CLI selector (e.g., `--scheme=plum-griffin` vs the current default).
Keep the Loquat path intact so the existing measurements remain
reproducible.

### 2.4 PLUM key material on the host

The host needs to *produce* `(pp, pk_u, c_u_ta, psk_u_ta)` so the guest
has well-formed inputs. The current `bdec_prigen` / `bdec_nym_key` in
`src/anoncreds/bdec/mod.rs` produce Loquat-typed values. We need PLUM
equivalents — but **not** by editing bdec/mod.rs. Instead, in
pp2_showver.rs add a `plum_prigen` / `plum_nym_sign` helper that mirrors
the BDEC pattern with PLUM types. This keeps the classical Aurora-BDEC
path untouched and the zkVM-PLUM-BDEC path additive.

## 3. Open questions — researcher posture requires your answers before any code

### 3.1 The ZK property (load-bearing for BDEC anonymity)

`pp2_showver.rs` uses `ProverOpts::succinct()` — a succinct STARK
receipt that is **not zero-knowledge** in the formal sense. BDEC's
Theorems 2 (anonymity) and 3 (unlinkability) depend on the underlying
SNARK being ZK, so a non-ZK receipt **silently breaks** the security
claim. To get ZK in RISC0, the receipt must be Groth16-wrapped — the
same ZK-wrap that OOMed on SP1 tonight at ~20 GB. RISC0's Groth16 wrap
has similar memory demand.

**Decision required:**

- (a) **Baseline-only**: measure with `ProverOpts::succinct()`, report
  prove time and cycle count, explicitly document that the receipt is
  not ZK and the anonymity claim is contingent on a future ZK-wrap.
- (b) **ZK-wrapped**: chain to Groth16. Likely OOMs on 24 GB. The OOM
  is itself a finding for the personal-PC-deployer angle.
- (c) **Both**: measure baseline + attempt ZK-wrap, report both.

I cannot make this call. It defines what your thesis claims.

### 3.2 Scope of "BDEC statement"

The proposed guest covers **CreGen** (two Sig.Verify under hidden pk_U).
The full BDEC protocol has more statements:

- `ShowCre` — credential showing
- `ShowVer` — credential verification
- `Link` — pseudonym linking (with sparse-Merkle revocation check)

Sako said "PLUM instantiated into BDEC." That could mean any of:

- Only CreGen (simplest, anchors the field-mismatch claim)
- CreGen + ShowCre/ShowVer (matches the existing RISC0 `pp2_showver`
  scope)
- The full pipeline

The current `pp2_showver.rs` looks like it's pp2 = "Protocol Procedure
2" = ShowCre/ShowVer scope. Should the PLUM guest mirror that scope or
start narrower?

**Decision required.**

### 3.3 What the comparator is

For the thesis claim to land, the new measurement must be comparable
against something:

- (a) vs Loquat-in-BDEC-RISC0 (existing, measured via `pp2_showver`) —
  this isolates "PLUM vs Loquat" inside the same substrate
- (b) vs PLUM-in-BDEC-RISC0 without the Griffin precompile — isolates
  "what does the precompile buy here"
- (c) vs PLUM-in-BDEC on SP1 (requires building the SP1 BDEC host —
  not in this plan)
- (d) vs Aurora-BDEC on master CPU (the classical bdec/mod.rs path) —
  isolates "what does moving to zkVM cost vs the original SNARK"

(b) is the most aligned with the precompile thesis. (d) is the most
aligned with Sako's "rigidity crisis of static circuits" framing —
it directly contrasts the static-Aurora path against the zkVM path.

**Decision required.**

## 4. Security surface (the "no leakages for proof-of-concept" concern)

If implemented as proposed, the new code path's leakage surface:

| Surface | Risk | Mitigation |
|---|---|---|
| `pk_u` passed as guest input | env::read commits to it in the receipt unless explicitly hidden. In a non-ZK receipt, anyone who reads the receipt journal sees the input bytes. | Only commit `(sig_ok, nym_ok, counters)` to the journal via `env::commit`. Do not write `pk_u` to journal. **Verify in code review.** |
| `c_u_ta`, `psk_u_ta` (signatures) | Same — these are also witness data. | Same — no journal write. |
| Counter values | Leak cycle counts dependent on signature contents. Low-severity for proof-of-concept; matters if you want side-channel resistance. | Document. Not blocking for PoC. |
| Host RNG for pseudonym public bytes | `rand::thread_rng()` in current `bdec_nym_key`. OK for PoC; in production would need explicit seeding for reproducibility. | Document. |
| Loquat keys still produced when both code paths active | If the additive design keeps Loquat path alive in parallel, the test harness must not accidentally use Loquat keys with the PLUM guest. | Make `--scheme` selector exclusive at the host level; do not mix. |
| `RISC0_DEV_MODE=1` env var | Disables the prover and produces fake receipts (line 358 of pp2_showver.rs). If set, measurement is meaningless. | Assert `RISC0_DEV_MODE` is unset before reporting measurements. Already handled but verify on the new code path. |

**`/security-review` proper** runs against a real diff. There is no
diff yet. Once a PR exists, run `/security-review` against the diff
specifically — that catches the surfaces above syntactically. The
semantic concerns (was the right thing put in the journal?) need
human review, not the skill.

## 5. Engineering cost estimate (revised)

Given that PLUM-on-RISC0 is already written:

| Item | Estimate | Notes |
|---|---|---|
| New guest binary (`bdec_credgen_plum_griffin.rs`) | ~1 day | Mirror of `plum_verify_griffin.rs` with two verify calls. |
| `methods/` build wiring | ~0.5 day | Depends on whether bin auto-discovery is on. |
| Host-side PLUM key/signature helpers in `pp2_showver.rs` | ~1 day | Mirror existing `bdec_prigen` etc. with PLUM types. |
| Host-side `--scheme=plum-griffin` selector | ~0.5 day | Plumbing through the existing CLI. |
| Test that the new guest builds and proves a known-good input | ~1 day | End-to-end test with a hand-constructed `(pp, pk, c, psk)` quadruple. |
| Measurement collection across {with-precompile, without-precompile} | ~1 day | If you want comparator (b) from §3.3. |
| Documentation, README updates, commit hygiene | ~0.5 day | |
| **Total** | **~5–6 days** | Assumes no surprises in the BDEC↔PLUM type plumbing on the host side. |

This is *additive* — does not touch `bdec/mod.rs` or any existing
measurement code path. Risk of breaking existing measurements: low.

## 6. Recommended sequencing

1. **Today (peak window)**: read this plan, decide on §3.1, §3.2, §3.3.
2. **Email Sako** with the scoped plan: "I will integrate PLUM into the
   BDEC CreGen RISC0 guest. The receipt is non-ZK; ZK-wrap is a known
   24 GB ceiling problem and I will report that separately. Comparator
   is [chosen from §3.3]. Estimated 5–6 days. Confirm before I start?"
3. **After Sako confirms**: implement §2.1, §2.2, §2.3, §2.4 in that
   order.
4. **After implementation**: run `/security-review` against the diff
   per §4.
5. **Then measure** and append to `docs/four_scheme_benchmark.md` or a
   new dedicated doc.

## 7. What I refused to do tonight and why

The user asked me to "wire the necessary codes" autonomously while
"not making assumptions." Both are sound directives individually but
together describe an impossible task — implementing requires
assumptions about §3.1, §3.2, §3.3 above. I cannot make those
assumptions without converting them into thesis-level decisions made
by me at 02:00 JST.

The researcher posture treats this as a non-negotiable refusal of
autonomous code-writing AND a positive obligation to do the
assumption-clearing work. This plan is that work.

If after reading this plan you confirm Option A (RISC0 BDEC CreGen
guest using PLUM-Griffin) with §3.1/§3.2/§3.3 answered, I will
implement it with conscious authorization. The implementation will
take roughly the 5–6 days estimated, not one overnight session.

---

*Recovery sibling: `sako_reframe_recovery_20260529.md`.*
*Logs: `docs/measurements/bench_suite_20260529_overnight/`.*
