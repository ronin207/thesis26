# Autonomous benchmark session 2026-07-03 — status + blocker

Written for the Operator's return. The benchmark loop is **stopped** on a blocker I
cannot resolve autonomously (below). The review deliverables (formalization + Sako)
completed and are the real output of this session.

## The blocker (why the CreGen prove never produced a number)

Every background prove was **killed externally** before reaching its ~35-min
overflow-or-complete decision point. Verified per run: **not** the `2^30` overflow,
**not** OOM (peak RSS ≤ 14 GiB on a 24 GiB machine), **not** a crash (stderr clean),
**not** my watchdog. The kill timing is **inconsistent**: 76 s, 86 s, 85 s, ~8 min,
and once ~35 min — so it is not a fixed idle timeout.

- `caffeinate` was active; machine stayed awake and idle-memory healthy (~15 GB free).
- Keep-alive `ScheduleWakeup` ticks (120–200 s, under the apparent window) helped
  **intermittently** (one run reached ~8 min) but did not reliably prevent the kill;
  the last run died ~50 s after an on-time active tick.
- The one run that survived ~35 min did so while I was taking many turns; but it too
  was eventually killed (during the overflow-retry hang).

**Conclusion:** long (`>` a few min) `run_in_background` Bash proves are being
terminated by something outside my control (harness/session/OS), unpredictably. I
cannot keep one alive to completion. **This needs your input** (see Open questions).

## What DID get fixed (pipeline debugging — real progress)

1. **iCloud EPERM** — sidestepped by pre-building and running the compiled binary
   from `.build-cache.nosync` (non-synced); confirmed your iCloud fix works too.
2. **dylib crash** — the binary needs `@rpath/liblibiop_c_api.dylib` but has no
   `LC_RPATH`; fixed via `DYLD_LIBRARY_PATH` + **direct exec** (routing through
   `/usr/bin/env` or `/usr/bin/time` strips `DYLD_*`). Binary now runs and proves.
3. **Runner hardened** — fail-fast watchdog on the `2^30` overflow (SP1 retries it
   forever otherwise) + a wall cap. Runner: `scratchpad/run_bench.sh`.

## What is NOT yet known (blocked by the above)

- **Whether CreGen prove is fixable by config.** `SHARD_SIZE` is **not** the lever
  (`2^22` and `2^20` both overflowed `2^30`). `HEIGHT_THRESHOLD=2^17` was the next
  lever to test but **no run survived long enough to reach the ~35-min overflow
  point**, so it is UNCONFIRMED.
- If `HEIGHT_THRESHOLD` also overflows, the `2^30` bound is fork-pinned by the
  cost-model mispricing (`rv64im_costs.json` prices the Griffin chip at 348 vs real
  ~3819 columns), and the fix is a fork edit (cost-model) or a fork revert to the
  6/11 state — **your Q2 call** (default was park-and-report).
- **ZK-wrap (computational-ZK story goal)** never started; it depends on a completing
  core prove and a ~51 h `vk_map` regen (multi-day).

## Completed this session (the deliverables)

- **Formalization diagnosis** (why "insufficient yet too long"): one failure — prose
  where formal objects belong. 2 blocking crypto-bar gaps: the central advantage
  `Adv^•_{zkVM-Cred}` is by-reference, never a boxed experiment (`055:46-52`); the
  five leaf errors are unquantified (`055:220-247`). Fix = lift the formal object to
  the point of claim, hedge once (rigor up + length down together).
- **Sako five-gate review** → `docs/sako_audits/log.md`. 2 blocking, both at the
  point of claim: (1) **RECURRING** — the central with/without-precompile comparison
  is not config-matched in the table+abstract (default OOM 1m45s vs tuned 14.25min;
  the config-matched 5h07m-DNF is buried in prose) — the curated-setting trap, and a
  prior prose-only "fix" is why it recurs; (2) abstract says "realised the BDEC
  construction" but §5 says non-statement-bound "functional benchmark".
- Both are **abstract/framing edits = your lane**; exact edits prepared, held for you.

## Open questions for you (to unblock)

1. **Long-prove execution:** are you (or something) killing my background jobs? Or is
   there a session/OS limit on long background processes? Options: you run the prove
   yourself via `!` in a prompt (survives in-session), authorize a detached/launchd
   approach, or run on other hardware. Without this, I can't get a CreGen number.
2. **Fork decision (Q2):** if config-tuning can't clear `2^30`, do I park (default),
   fix the cost-model (348→3819, a fork edit), or revert to the 6/11 fork?
