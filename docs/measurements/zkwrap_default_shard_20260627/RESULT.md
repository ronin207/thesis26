# ZK-wrap default-SHARD_SIZE disentangling run (SP1 PLUM-verify)

Date: 2026-06-27. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB
(`hw.memsize=25769803776`). Non-destructive (process panicked; no system kill).
Continues `docs/measurements/zkwrap_worker_concurrency_20260627/`.

## Question (the disentangling experiment)
The prior runs (quartered `SHARD_SIZE=1<<22`, workers 2 and 1) both died on a
recursion reduce-shape panic `fixed height is too small`. That run HYPOTHESIZED
the quartered shards were the cause. This run changes EXACTLY ONE variable:
use the **default `SHARD_SIZE` (unset → `1<<24`)**, holding workers=2. Does
un-quartering clear the shape panic, and if so does core memory then stay <24 GB?

## Config (n=1)
PLUM-80, λ=80, arm=`syscall` (**Griffin Fp192 precompile ON**, Cell 2),
`PLUM_ZK_WRAP=plonk`, **`SHARD_SIZE` UNSET → default `1<<24`**
(verified: `crates/core/executor/src/opts.rs:75-76`, `MAX_SHARD_SIZE = 1<<24`
at `opts.rs:9`), `SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`,
`SP1_WORKER_NUM_CORE_WORKERS=2`, `SP1_PROVER=cpu`, in-process CPU prover.
Binary `target/release/plum_host` built 2026-06-27 17:51 (SP1 submodule HEAD
`8bf0248`). Instrumentation: Python wrapper, `getrusage(RUSAGE_CHILDREN).ru_maxrss`
(bytes/macOS, authoritative) + 3 s ps-rss sampler with UTC timestamps.
Wrapper: `run.py` (this dir). Raw: `defshard_w2.log`, `.rss.tsv`, `.meta`.

## Result: rc=-6 (PANIC), wall 30.33 min, maxRSS 16.509 GiB, sampler peak 15.950 GiB @ 12:44:00

### The panic — IDENTICAL heights to the quartered run
```
recursion/machine/src/chips/alu_ext.rs:99
  fixed height is too small: got height 795264 for number of rows 1064022
recursion/machine/src/chips/prefix_sum_checks.rs:95
  fixed height is too small: got height 224608 for number of rows 263400
```
These are **byte-for-byte identical** to the prior quartered `workers2` run
(`zkwrap_worker_concurrency_20260627/RESULT.md` lines 63-64). Default
`SHARD_SIZE` did **NOT** change the overflow numbers AT ALL.

### Root cause traced to source (not just an exit code)
The fixed height is the per-chip trace capacity assigned from a recursion
shape; overflow panics at `crates/hypercube/src/util.rs:50-58`
(`if n > height { panic!("fixed height is too small ...") }`).
The reduce shape is selected by `retrieve_or_compute_reduce_shape`
(`crates/prover/src/shapes.rs:184`) →
`compress_proof_shape_from_arity(DEFAULT_ARITY)` (`shapes.rs:302`), which
**`include_bytes!("../compress_shape.json")`** — a STATIC shape baked into the
binary, keyed ONLY on the recursion arity (`DEFAULT_ARITY = 4`, `shapes.rs:71`).
The committed `crates/prover/compress_shape.json` reads verbatim:
`{"heights":{ "ExtAlu":795264, "PrefixSumChecks":224608, "BaseAlu":592384,
"Select":1087808, "MemoryConst":492320, "MemoryVar":661984,
"Poseidon2WideDeg3":158368, "PublicValues":16 }}`.
`ExtAlu 795264` and `PrefixSumChecks 224608` ARE the panic heights. The
overflow is hard-baked into the binary's shape registry; it is a function of
the **arity-4 compose program**, NOT of `SHARD_SIZE`, NOT of shard count,
NOT of worker count.
Even SP1's own hardcoded fallback shape (`shapes.rs:332`, ExtAlu = 850_000)
is STILL < the required 1_064_022 — the needed shape is larger than any value
committed anywhere in this fork.

## Stage-reached map (proof-system layer)
| Stage | IOP / argument | Reached? |
|---|---|---|
| **CORE STARK** | per-shard RISC-V + chip AIRs, FRI over SP1Field | YES, COMPLETED. Core peak 15.7 GiB @ 12:35:23, then RSS dropped (core→recursion transition). |
| **NORMALIZE (recursion leaves)** | recursive STARK verifying each core shard | YES. ~12:35–12:59, RSS oscillating 2–16 GiB across many leaf proofs. No jetsam kill. |
| **COMPRESS/REDUCE (compose, arity-4)** | recursive STARK verifying a batch of 4 recursion proofs | **REACHED, FAILED HERE.** Trace-height assignment for the compose program overflowed the committed ExtAlu (need 1,064,022 > 795,264) and PrefixSumChecks (need 263,400 > 224,608) capacities. |
| **SHRINK** | compress to constant size | NO. |
| **WRAP** | re-prove in BN254-friendly circuit | NO. |
| **gnark PLONK** | final SNARK over BN254 | NO — still unmeasured. |

Proof-system reading of the failure: the arity-4 compose verifier is a FIXED
arithmetic circuit whose per-chip column heights are committed ahead of time
(compress_shape.json is the fixpoint shape "big enough that the compose program
verifying 4 proofs-of-this-shape fits this shape"). The actual compose witness
for this machine exceeds the committed ExtAlu height. Exact analogue: a
polynomial-commitment / circuit sized for degree ≤ N handed a degree-(N+k)
polynomial — the encoding capacity is exceeded and the prover cannot even
FORM the trace, let alone commit/open it. This is a CAPACITY (structural) wall,
not a RAM wall.

## Verdict
1. **Did default SHARD_SIZE clear the recursion-shape panic? NO.** The prior
   run's hypothesis ("quartered shards cause the shape panic") is **REFUTED**.
   The overflow heights are identical at `1<<22` and `1<<24`. Combined with the
   prior run's worker-independence (identical at workers 2 and 1), the panic is
   now shown to be **independent of SHARD_SIZE AND worker count** — it is fixed
   by the arity-4 compose program + the baked-in shape registry.
2. **Furthest stage reached:** CORE (complete) → NORMALIZE recursion (complete-ish)
   → COMPRESS/REDUCE compose node (failed at trace-shape assignment). One stage
   deeper in wall-time than the quartered runs (panic at 29.7 min vs ~6–7 min)
   only because default shards make each core+normalize proof ~4× heavier; the
   structural failure point is the SAME compose node.
3. **Current binding blocker (proof-system layer):** the **arity-4 COMPRESS/REDUCE
   recursive-STARK shape capacity** (`compress_shape.json` ExtAlu/PrefixSumChecks
   too small for this machine's compose witness). It is a **STRUCTURAL/CAPACITY
   wall, NOT a RAM wall.** Through every stage actually reached, RAM was a
   non-issue at workers=2: maxRSS 16.5 GiB, no jetsam kill, "memory high ~80%"
   warnings only — comfortably inside 24 GB.
4. **Is 24 GB a live path for PLUM-verify ZK-wrap?** The question is now
   **MOOT on this fork as shipped**: the pipeline cannot STRUCTURALLY reach the
   gnark wrap, so its peak RAM stays unmeasured for a reason that has nothing to
   do with RAM. The more interesting finding stands: the binding constraint is
   the precomputed recursion shape registry, not memory. It is **config-fixable
   in principle** — `shapes.rs:943` documents regeneration via
   `cargo test --release -p sp1-prover --features experimental -- test_find_recursion_shape --include-ignored`,
   which would rewrite compress_shape.json to a larger fixpoint — but as the
   binary ships, it is a hard wall regardless of how much RAM is available.

## Leading structural hypothesis for WHY this fork's shape is too small (UNTESTED)
The compose program verifies recursion proofs of the CORE machine. This arm
runs the **custom Griffin Fp192 precompile chip** added to the core machine.
A larger core machine ⇒ larger core/normalize recursive verifier ⇒ larger
compose ExtAlu/PrefixSumChecks counts. The committed compress_shape.json was
near-certainly generated for the STOCK SP1 machine (no custom precompile) and
not regenerated for the extended machine. If true, this is a sharp
"precompile-paradox"-flavored finding: the precompile that accelerates CORE
proving (Cell 2) overflows the recursion-shape budget required for the ZK wrap.
**Disambiguating run (not done, budget):** the SHA-3 / no-precompile arm taken
to the compose stage — if it ALSO overflows at 1,064,022, the cause is a
fork-wide stale shape; if it fits, the precompile is the cause. No
non-precompile compose-stage datapoint currently exists (the 2026-05-29
baseline OOM'd before the shape check).

## Five-attack
- **Source.** maxRSS from `getrusage(RUSAGE_CHILDREN).ru_maxrss` (bytes/macOS,
  single child = that child's peak); ps-rss sampler cross-check holds
  (sampler 15.95 ≤ getrusage 16.51 GiB). Panic heights read from the log AND
  independently matched to the static `compress_shape.json` (ExtAlu 795264,
  PrefixSumChecks 224608 — exact). FIRED: I did NOT independently re-derive
  that 1,064,022 is workload-independent by running a second workload; it is
  inferred from the arity-4 compose program being workload-independent by
  construction.
- **Assumption.** FIRED, and productively: "quartering causes the panic" is now
  MEASURED-REFUTED (identical heights at both SHARD_SIZE). "Precompile enlarges
  the verifier" is an UNTESTED hypothesis — no non-precompile compose datapoint.
- **Failure-mode.** FIRED. getrusage undercounts compressed-page pressure
  (prior run's lesson), but here the proximate failure is unambiguous: a Rust
  panic (rc=-6), not an OOM-kill; no jetsam, warnings only ~80%. The structural
  diagnosis does not depend on the RAM number being tight.
- **Structure.** Did not fire on the core experiment (clean: only SHARD_SIZE
  changed vs the prior workers2 run). FIRED on cause-attribution: cannot
  distinguish fork-wide-stale-shape vs precompile-enlarged-verifier without the
  non-precompile compose run.
- **Frontier.** FIRED. Whether regenerating compress_shape.json actually closes
  the gap on THIS machine config is unverified — the hardcoded fallback
  (ExtAlu 850,000) is ALSO < 1,064,022, hinting the required shape is
  substantially larger than anything committed, i.e. possibly a deeper
  machine/shape mismatch rather than a simple stale file.

## Cost
~31 min machine time: this run 30.33 min (no rebuild; reused 17:51 binary) +
shape-registry source tracing. n=1.
