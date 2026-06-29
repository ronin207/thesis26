# Tier-1 reproducibility fix — Cell 2 faithful Griffin count (2026-06-29)

## Problem
At HEAD, `PlumGriffinHasher::USE_GRIFFIN_FS = true` (commit ff77120) routed
Fiat–Shamir through the Griffin sponge, which re-absorbs the whole transcript
per challenge (quadratic). The zkVM guest inherited this, so execute-mode
Cell 2 reported `griffin_fp192 = 6575` / `cycles = 147,326,605` — NOT the
thesis's faithful Cell 2 number (Griffin-for-hashing + SHAKE256-for-FS =
**1,052 Griffin perms / 125,504,123 cycles**, measured May before ff77120).
`USE_GRIFFIN_FS = true` is genuinely required by the Stage-4c-4 circuit gate
test `griffin_fs_sign_then_verify_accepts_and_rejects_tamper`, so the flag on
`PlumGriffinHasher` must stay true.

## Fix — decouple via newtype delegation
New hasher type `PlumGriffinShakeFsHasher` (newtype over `PlumGriffinHasher`)
delegates all hashing (new/update/finalize/compress_pair, and the default
hash_bytes/hash_fields) to the identical Griffin implementation but overrides
`USE_GRIFFIN_FS = false` (SHAKE256 byte path for FS). The zkVM runtime path
(guest verify + host sign) moves to this type; `PlumGriffinHasher` and its
`USE_GRIFFIN_FS = true` are untouched, so the circuit gate is intact.

Newtype delegation chosen over a macro/shared-trait-impl: only the const and
three thin forwarders differ, the wrapped type already encapsulates the Griffin
logic, and the default trait methods (`hash_bytes`/`hash_fields`) inherit
correct behavior for free — zero hash-logic duplication.

### Files changed (diffstat)
```
 platforms/zkvms/sp1/program/src/main.rs         |  6 +++-
 platforms/zkvms/sp1/script/src/bin/plum_host.rs | 11 ++++---
 src/primitives/hash/hasher_plum.rs              | 42 +++++++++++++++++++++++++
 3 files changed, 54 insertions(+), 5 deletions(-)
```

- `src/primitives/hash/hasher_plum.rs` — add `pub struct PlumGriffinShakeFsHasher(PlumGriffinHasher)` + its `PlumHasher` impl (`USE_GRIFFIN_FS = false`; new/update/finalize_bytes/compress_pair delegate to `PlumGriffinHasher`). Re-exported automatically via `signatures::plum::hasher` (= `primitives::hash::hasher_plum`).
- `platforms/zkvms/sp1/program/src/main.rs` — guest's `not(plum-sha3-hasher)` arm now `use … PlumGriffinShakeFsHasher as Hasher` (was `PlumGriffinHasher`).
- `platforms/zkvms/sp1/script/src/bin/plum_host.rs` — host's Griffin-arm signature now `plum_sign::<PlumGriffinShakeFsHasher, _>` (was `PlumGriffinHasher`); import updated. Required because the host-generated signature must match the guest's FS path, else verify rejects (observed mid-fix: `accepted=false`, `griffin_fp192=0`).

`PlumGriffinHasher` (`USE_GRIFFIN_FS = true`, hasher_plum.rs:91) left untouched.

## Environment
- SP1 submodule HEAD: `8bf0248bc5b6b7ba7c820253c3918ea277008641`
- hardware: MacBook Pro M5 Pro, 24 GB RAM
- λ = 80 (PLUM_SECURITY=80), execute-mode only (no proves)

## Before / after (execute-mode Cell 2, syscall arm)
| metric | before (HEAD) | after | faithful target |
|---|---|---|---|
| griffin_fp192 | 6575 | **1052** | 1,052 |
| cycles | 147,326,605 | **125,506,731** | 125,504,123 |
| accepted | true | true | — |

(After-cycles differ from the May reference by 2,608 cycles = 0.002%; griffin
count is exact.)

## Verification gates — all PASS

### Gate 1 — `cargo build --release --bin plum_host` — PASS
```
=== GATE 1: build plum_host ===
    Finished `release` profile [optimized] target(s) in 4m 18s
```

### Gate 2 — circuit gate test (4c-4) — PASS
```
running 1 test
test signatures::plum::verify::tests::griffin_fs_sign_then_verify_accepts_and_rejects_tamper has been running for over 60 seconds
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 289 filtered out; finished in 61.35s
```

### Gate 3 — execute Cell 2 (PLUM_PROVE_ARM=syscall, PLUM_SECURITY=80) — PASS (lands at 1052)
```
accepted=true cycles=125506731 elapsed_ms=1846 syscalls=70448 uint256_mul=69396 griffin_fp192=1052
```

### Gate 4 — execute Cell 3 (sha3 arm) — PASS (unchanged)
```
accepted=true cycles=110798116 elapsed_ms=1295 syscalls=69385 uint256_mul=69385 griffin_fp192=0
```

### Gate 5 — workspace compiles (`cargo check`) — PASS (warnings only, pre-existing)
```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.51s
```
