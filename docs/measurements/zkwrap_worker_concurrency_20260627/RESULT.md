# ZK-wrap worker-concurrency RAM experiment (SP1 PLUM-verify)

Date: 2026-06-27. Operator machine: Mac17,9 (M5 Pro, 18 cores), 24 GB
(`hw.memsize=25769803776`). Non-destructive (OOM/jetsam just kills the process).

## Question
Does lowering SP1's recursion/core worker-pool concurrency
(`SP1_WORKER_NUM_RECURSION_PROVER_WORKERS`, default 8;
`SP1_WORKER_NUM_CORE_WORKERS`, default 4) drop the ZK-wrap
core+recursion peak RAM below the ~20 GB jetsam floor, so the
`.plonk()` wrap on PLUM-verify can START within 24 GB?

## Step 0 — env vars ARE honored on the in-process prove path (CONFIRMED)
Code trace (SP1 fork at `submodules/sp1`, v6.2.1, routed via the
`[patch.crates-io]` table in `platforms/zkvms/sp1/Cargo.toml:34-`):
`ProverClient::from_env()` with `SP1_PROVER` unset defaults to `"cpu"`
(`crates/sdk/src/blocking/env/mod.rs:105-110`) →
`CpuProver::new_with_opts_and_machine` (`crates/sdk/src/blocking/cpu/mod.rs:96-110`)
→ `cpu_worker_builder_with_machine` (`crates/prover/src/worker/builder.rs:328`)
→ `SP1WorkerBuilder::new_with_machine` → `SP1WorkerConfig::new`
(`crates/prover/src/worker/config.rs:84` reads `SP1_WORKER_NUM_CORE_WORKERS`,
`:132` reads `SP1_WORKER_NUM_RECURSION_PROVER_WORKERS`).
So the local `client.prove(&pk,stdin).plonk().run()` path
(`plum_host.rs:355-359`) DOES consult both vars. Experiment is valid.
Caveat: `cpu_worker_builder_with_machine` also hardcodes a shared
`ProverSemaphore::new(4)` (builder.rs:332) capping concurrent provers at 4;
since we LOWER workers to 2/1, the worker count is the binding constraint.

## Config (held fixed across all runs)
PLUM-80, λ=80, arm=`syscall` (Griffin precompile ON), `PLUM_ZK_WRAP=plonk`,
`SHARD_SIZE=4194304` (quartered, `1<<22`; default is `1<<24` — matches the
prior baseline `03_plonk_zkwrap_quartered_*`), `RUST_LOG=info`, `SP1_PROVER=cpu`,
in-process CPU prover. ONLY changed variable: the two worker counts.
Instrumentation: Python wrapper reading `getrusage(RUSAGE_CHILDREN).ru_maxrss`
(bytes on macOS — authoritative peak RSS) + a 3 s ps-tree sampler (cross-check).
NB the prior `.rss.tsv` sampler tracked wrapper PIDs (peaked ~1 MB, useless);
and `/usr/bin/time -l` could NOT be used because it is SIP-protected and strips
`DYLD_LIBRARY_PATH` (the host needs `liblibiop_c_api.dylib` via @rpath with no
LC_RPATH). The Python wrapper (non-SIP) preserves DYLD and reads getrusage.

## Results
| run | RW | CW | maxRSS (getrusage) | sampler peak | wall | exit |
|---|---|---|---|---|---|---|
| baseline (logged 2026-05-29) | 8 | 4 | 19976421376 B = 18.60 GiB | (n/a) | ~19.9 min | JETSAM-KILLED (mem pressure) |
| workers2 | 2 | 2 | 18579390464 B = 17.30 GiB | 15.61 GiB | 21.62 min | rc=-6 PANIC (recursion shape) |
| workers1 | 1 | 1 | 17769316352 B = 16.55 GiB | 16.37 GiB | 28.20 min | rc=-6 PANIC (recursion shape) |

Baseline source: `docs/measurements/bench_suite_20260529_overnight/03_plonk_zkwrap_quartered_with_rss_sampler.log`
(`/usr/bin/time -l` maxRSS 19976421376 B; "command terminated abnormally";
"peak memory footprint" 96395253696 B = 89.8 GB → heavy compressor thrash → jetsam).

### Two findings
1. Lowering workers monotonically drops peak maxRSS: 18.60 → 17.30 → 16.55 GiB
   (8→2→1), a ~2 GiB / -11% reduction. Modest. Going 2→1 does NOT lower the
   core-phase peak (sampler ~15.6/16.4 GiB both) — the core peak is a
   single-shard floor set by SHARD_SIZE, not by worker count.
2. DECISIVE: both low-worker runs ESCAPED THE JETSAM KILL that ended the
   baseline. They survived the core + early-recursion phase and progressed
   FURTHER, then died on a deterministic, worker-INDEPENDENT Rust panic in
   the recursion machine (identical on workers=2 and workers=1):
   `submodules/sp1/crates/recursion/machine/src/chips/prefix_sum_checks.rs:95`
   and `.../alu_ext.rs:99`:
   `fixed height is too small: got height 224608 for number of rows 263400`
   `fixed height is too small: got height 795264 for number of rows 1064022`
   This is a recursion reduce-shape capacity overflow, NOT an OOM.

## Verdict
(a) Peak below 20 GB? The process maxRSS was already <20 GB at baseline (18.6),
    yet baseline was jetsam-killed by SYSTEM memory PRESSURE (89.8 GB phys
    footprint via compression). Lowering workers cut maxRSS to 16.5-17.3 GiB
    AND, decisively, removed the jetsam kill. So the worker lever DOES relieve
    the memory wall that blocked the baseline.
(b) Did the wrap stage start? NO. Both runs died in the recursion (compress/
    reduce) phase, before shrink → gnark wrap. No gnark/plonk-circuit marker
    ever appeared.
(c) Did the gnark wrap itself fit? UNTESTED — never reached.
(d) NET: 24 GB is STILL NOT demonstrated viable for the PLUM-verify ZK-wrap —
    but the binding blocker has MOVED. It is no longer a RAM wall in
    core/recursion (the worker lever clears that); it is now an orthogonal
    recursion reduce-shape overflow ("fixed height is too small") that is
    HYPOTHESIZED (not yet verified) to be caused by the quartered SHARD_SIZE
    producing more core shards than the precomputed fixed reduce shapes admit.
    The shard-quartering memory mitigation appears INCOMPATIBLE with the
    precomputed recursion shapes in this SP1 fork.

## Five-attack
- Source: maxRSS from getrusage RUSAGE_CHILDREN.ru_maxrss (bytes/macOS),
  single child = that child's peak; baseline from `/usr/bin/time -l` (also
  getrusage bytes). Same units (/1024^3). Cross-check: getrusage ≥ sampler
  (sampler undersamples) holds. FIRED: baseline binary is 2026-05-29 vintage;
  source changed since, and baseline OOM'd before the shape check, so we
  cannot know if the baseline binary had the same shape bug.
- Assumption: FIRED. "Quartered SHARD_SIZE causes the shape panic" is an
  INFERENCE, not a measurement — I did not run default SHARD_SIZE. What IS
  measured: the panic is worker-independent (identical on 2 and 1).
- Failure-mode: FIRED. maxRSS undercounts compressed-page pressure; the
  jetsam-survival (not the 2 GiB maxRSS delta) is the more decisive signal.
- Structure: did not fire for the worker-lever comparison (clean apples-to-
  apples, no confound found); DID fire for cause-isolation — the missing run
  is default-SHARD_SIZE + low workers.
- Frontier: FIRED. The shard-count → reduce-shape-height mechanism is inferred
  from the panic text, not from reading `retrieve_or_compute_reduce_shape`.

## Next measurements (not run; budget)
1. workers=2 + DEFAULT SHARD_SIZE (unset) — disentangle: does the shape panic
   vanish (confirming quartering is the cause) and does core then re-OOM?
2. If shape panic is quartering-induced: get past it (regenerate/enlarge
   recursion fixed shapes, or `SP1_WORKER_MAX_COMPOSE_ARITY`) to finally reach
   and measure the gnark plonk-wrap peak RAM (the still-open decision unknown).

## Cost
~75 min machine time: build 4m24s + workers2 21.6 min + workers1 28.2 min +
two early misconfigured starts (dyld/SIP, ~0 cost) + monitoring overhead.
