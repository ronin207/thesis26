# Precompile-paradox mechanism diagnostic — Step 0 verdict: the proposed control arm is INVALID

Date: 2026-06-27. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB.
No prove run executed (deliberately — see verdict). Source-tracing only.
SP1 submodule HEAD `8bf0248`. Continues
`docs/measurements/zkwrap_default_shard_20260627/RESULT.md`.

## Question
Is the arity-4 COMPRESS/REDUCE shape overflow (`compress_shape.json` ExtAlu need
**1,064,022 > provisioned 795,264**) caused by the custom **Griffin Fp192
precompile** enlarging the core machine (the "precompile paradox"), or is it a
fork-wide / PLUM-relation-size issue independent of the Griffin chip?

## Step 0 — MECHANISM (decided BEFORE choosing a config, as instructed)

**Result: CASE (a), in its strongest form.** The recursive COMPOSE verifier's
trace heights — including the ExtAlu height that overflows — are a **BUILD
CONSTANT fixed by the compiled-in machine + the static shape registry**. They
are **independent of which chips the guest execution exercises**, and even
independent of the witness VALUES. Evidence, file:line:

1. **The runtime reduce-shape is the static committed file, keyed ONLY on the
   full machine + arity — never on the guest.**
   `crates/prover/src/worker/config.rs:144-145`:
   `reduce_shape = SP1RecursionProofShape::retrieve_or_compute_reduce_shape(machine, max_compose_arity)`.
   `retrieve_or_compute_reduce_shape` (`crates/prover/src/shapes.rs:184-194`)
   asserts `machine.chips() == RiscvAir::<SP1Field>::machine().chips()` (the full
   default machine, Griffin chips included) and returns
   `compress_proof_shape_from_arity(max_arity)` →
   `include_bytes!("../compress_shape.json")` (`shapes.rs:302-306`). No guest,
   no execution trace, no exercised-chip set enters this path.

2. **Every recursion program (normalize AND compose) is stamped with that one
   static shape.** `crates/prover/src/shapes.rs:551` and `:568`:
   `program.shape = Some(reduce_shape.clone().shape);` — applied uniformly to
   the Normalize program (`:549-552`) and the Compose program (`:563-569`).

3. **The COMPOSE program is built from a STATIC DUMMY input, not from the actual
   normalize proofs of the run.** `crates/prover/src/shapes.rs:554-567`: the
   `Compose(arity)` arm calls
   `dummy_compose_input(&compress_verifier, &compress_proof_shape_from_arity(max_arity), arity, height)`
   then `compose_program_from_input(&recursive_compress_verifier, true, &dummy_input)`.
   The compose program is therefore a FIXED arithmetic circuit verifying
   `arity` proofs-of-the-committed-shape. A fixed verifier circuit performs a
   FIXED number of field operations regardless of witness values → its ExtAlu
   trace height (1,064,022) is a property of the build, not of the run.

4. **Griffin is unconditionally compiled into the machine; there is NO feature
   gate.** `crates/core/machine/src/riscv/mod.rs:478-481` (4 Griffin chips added
   to the `RiscvAir` enum) and `:612-615` (the `[GriffinFp192, GriffinFp192Control]`
   precompile cluster). Only `mprotect` is `cfg`-gated anywhere in that file.
   So the Griffin AIR is in the machine whether or not a guest exercises it.

**Consequence for the proposed diagnostic.** The intended SHA-3 control arm
(PLUM with stock SHA-256 instead of Griffin) runs the *same binary*. It therefore
hits the *same* arity-4 compose program with the *same* 1,064,022 ExtAlu
requirement and *same* 795,264 provision → the *byte-identical* panic. It
exercises a different *core* cluster, but the compose node never sees that — the
compose shape is fixed upstream of execution. **The SHA-3 arm cannot isolate the
Griffin chip. Running it would burn ~13-30 min re-confirming a known panic and
prove nothing about attribution.** Per the Step-0 instruction
("don't run an invalid diagnostic"), it was NOT run.

The emulated/no-precompile arm is independently non-viable: Cell 1 DNF'd at
7.08B cycles before reaching compose.

## Step 1 — control arm: NOT RUN (invalid per Step 0). No new wall-time spent on proving.

## Step 2 — what the mechanism implies, and the residual attribution gap

- **CONFIRMED (proof-system layer):** the binding blocker is that the committed
  `crates/prover/compress_shape.json` is **not a valid fixpoint** for this fork's
  recursion verifier. It provisions ExtAlu = 795,264, but the arity-4 compose
  program built against it requires 1,064,022. This is a STRUCTURAL/CAPACITY wall
  (a circuit sized for degree ≤ N handed a degree-(N+k) witness), confirmed in
  the prior run and now mechanistically explained: the shape is a static,
  build-time, guest-independent constant. The wall has nothing to do with RAM
  (prior run: maxRSS 16.5 GiB, no jetsam, comfortably < 24 GB).

- **Staleness is real and traced.** `compress_shape.json` was last modified by an
  UPSTREAM commit (`ca6159a05`, "remove deprecated syscalls (#1127)"). The 22
  Griffin fork commits (`299b58894 … 8bf0248bc`) were layered on top WITHOUT
  regenerating it. Stock SP1 CI enforces this file is a valid fixpoint via
  `test_core_shape_fit` (`crates/prover/src/shapes.rs:933-1010`, which recomputes
  `max_cluster_count` over ALL `chip_clusters` and errors `CoreShapesTooLarge` if
  the committed shape is too small). So at the upstream base the file WAS valid;
  in the fork it is not.

- **Attribution to Griffin is UNPROVEN — and NOT provable by any same-binary run.**
  The fork's delta from the upstream shape-base is NOT Griffin-only. A
  `git diff --stat ca6159a05..HEAD` over the verifier paths shows non-trivial
  changes to the recursion verifier circuit and shape machinery *beyond* the
  precompile, e.g. `crates/recursion/circuit/src/machine/core.rs` (+37),
  `crates/recursion/circuit/src/machine/compress.rs` (+29),
  `crates/prover/src/shapes.rs` (+572). (Caveat: this span also straddles an
  upstream merge, so it over-counts; the point stands that the delta is not
  cleanly Griffin.) Any of these could independently enlarge the compose ExtAlu
  requirement. Therefore the overflow could be (i) the Griffin chips enlarging
  the core machine → larger normalize verifier → larger compose, OR (ii) a
  fork/upstream verifier-circuit change, OR (iii) both. The same-binary SHA-3 run
  cannot separate these, because all three live in the binary regardless of guest.

## Verdict

- **Precompile-paradox hypothesis: UNDISAMBIGUATED**, and — the load-bearing
  finding — **the originally-proposed SHA-3 control run cannot disambiguate it**
  (the compose shape is fixed upstream of guest execution; case (a)).
- **Binding blocker (whose layer):** SP1's **static recursion shape registry**
  (`compress_shape.json`) not being a valid fixpoint for this fork's compose
  verifier. It lives in **SP1's prover/shape layer**, entangled with the fork's
  recursion-verifier deltas — **NOT cleanly attributable to my Griffin
  precompile, and NOT a RAM wall.**
- **gnark / wrap peak RAM:** still UNREACHED and UNMEASURED. The pipeline cannot
  structurally pass COMPRESS/REDUCE as the binary ships. 24 GB remains MOOT for
  this question (blocked by a capacity wall, not memory).

## The ONLY valid experiments (what it would take — none is a guest swap)

1. **Decisive + actionable (recommended): regenerate the shape on the CURRENT
   machine.** `cargo test --release -p sp1-prover --features experimental --
   test_find_recursion_shape --include-ignored` (the fix documented at
   `crates/prover/src/shapes.rs:943`). This rewrites `compress_shape.json` to the
   true fixpoint for the Griffin-included machine AND logs `max_cluster_count`.
   - If the regenerated ExtAlu ≥ 1,064,022: the committed file was simply STALE;
     regenerating it UNBLOCKS the pipeline → can then reach SHRINK/WRAP/gnark and
     finally measure the wrap peak RAM (the long-sought 24 GB datapoint).
   - Cost: an sp1-prover test build + a vk/shape search. Mutates a committed file
     (`compress_shape.json`) — needs explicit authorization. Build/run time
     unbounded-uncertain; did NOT run it unprompted within this diagnostic's
     budget.
2. **To attribute to Griffin SPECIFICALLY (the precompile-paradox claim):**
   add a `#[cfg(feature = "griffin")]` gate around the 4 Griffin chips
   (`riscv/mod.rs:478-481`) and the cluster (`:612-615`), regenerate the shape
   WITHOUT the feature, and compare the required ExtAlu to the WITH-Griffin
   regeneration. Only this controlled BUILD (not a guest swap) isolates the
   precompile's contribution to the compose-verifier size.

## Five-attack
- **Source.** Mechanism read directly from fork source (config.rs:144-145,
  shapes.rs:184-194/302-306/549-568, riscv/mod.rs:478-481/612-615), not inferred
  from logs. Overflow heights (1,064,022 / 795,264) from the prior run's log +
  the committed JSON. FIRED: I did not execute a run to re-observe the panic this
  session — relying on the prior measured panic + the now-proven build-constant
  argument.
- **Assumption.** FIRED productively: the prior run's leading hypothesis
  ("precompile enlarges the verifier → paradox") is shown to be **not testable by
  the proposed SHA-3 run**, and only partially supported (fork has non-Griffin
  verifier deltas). Downgraded from "leading hypothesis" to "one of ≥3 causes,
  needs a controlled build."
- **Failure-mode.** FIRED. The trap was running an expensive arm that LOOKS like
  a control but shares the fixed compose program → false negative/positive either
  way. Avoided.
- **Structure.** FIRED. The valid control is a different BUILD (feature-gate or
  shape regen), not a different GUEST — a category the original plan conflated.
- **Frontier.** FIRED. Whether regeneration actually closes the gap on this
  machine is unverified; the hardcoded fallback (ExtAlu 850,000, shapes.rs:333)
  is ALSO < 1,064,022, hinting the true fixpoint is substantially larger than any
  committed value — consistent with a verifier-circuit change, not only +4 chips.

## Cost
~0 prove minutes (no run executed — the proposed run was proven invalid first).
~25 min source tracing. n/a runs.
