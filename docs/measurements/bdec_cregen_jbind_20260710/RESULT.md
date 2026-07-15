# CreGen jbind prove — statement-bound receipt (2026-07-10)

**Result (log: `cregen_jbind_run.log`):**
```
accepted=true  statement_bound=true  prove_ms=3963267 (= 66.05 min)
proof_bytes=1504198020 (~1.50 GB, serialized core STARK)  RUN_RC=0  END 2026-07-10T08:10:04Z
```

## What ran
- Bin `bdec_cregen_host`, `BDEC_HOST_MODE=prove-jbind`, λ=80, **synthetic witness** (fresh PLUM key + hardcoded messages). Message content does NOT affect the relation or cost, so this is valid for the measurement (real attributes would give the same prove time).
- Config (as `scripts/run_showcre_wrap.sh`): `SP1_PROVER=cpu`, `SHARD_SIZE=1048576`, `RAYON_NUM_THREADS=8`, `ELEMENT_THRESHOLD=2^26`, `HEIGHT_THRESHOLD=2^16`, `TRACE_CHUNK_SLOTS=2`, `SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`. `CARGO_TARGET_DIR=.build-cache.nosync`.
- Launch: detached (`nohup` + `caffeinate -dims` + memory guard) via `scripts/run_cregen_jbind.sh`.

## Meaning
- `statement_bound=true`: the host recovered `x_cre=(c_{U,TA},h_{U,TA},ppk_{U,TA})` from the receipt journal and bind-checked it against the input; the jbind guest commits `x_cre`, and `w_cre=(pk_U,psk_{U,TA})` stays a private witness.
- **Closes the "functional benchmark, not statement-bound" caveat (§5/§6/§8) for CreGen**: a statement-bound CreGen receipt proves in **66.05 min** at λ=80 on the M-series MacBook.
- Core STARK prove (`client.prove().run()`), **NOT zero-knowledge** (per Succinct docs); ZK/anonymity requires the wrap. `proof_bytes ~1.5 GB` is the raw core STARK; the wrap compresses to O(1).
- **CPU-only**: SP1's GPU prover is CUDA/NVIDIA only (no Metal/Apple-Silicon backend), so on the MacBook target CPU is forced — these are the honest consumer-hardware numbers.

## Operational note (why prior attempts failed)
- The earlier inline runs were killed ~5 min in by Claude's own background-task tooling, **NOT** by memory (this run had the same ~14–16 GB available; the memory guard never fired).
- Fix: launch long runs **detached** (`nohup` + `disown`, reparented to init) — either via `run_cregen_jbind.sh` in a user Terminal, or a foreground call to that script (which exits immediately after detaching). Do NOT run a multi-hour prove as an inline `run_in_background` task.
