# BDEC end-to-end, k=2 two-issuer, statement-bound (jbind) — RESULT

**Run:** BDEC full credential flow as SP1 guests, all three relations
statement-bound (`jbind`), core STARK proves (`.run()`, **not** ZK-wrapped).
**Date:** 2026-07-10 (START 16:30:23Z → END 20:57:27Z, wall **4 h 27 m**).
**Security parameter:** λ = 80 (`BDEC_HOST_SECURITY=80`).
**Machine:** target hardware (24 GB), `SP1_PROVER=cpu` (no CUDA on macOS).
**Exit:** `RUN_RC=0`, clean; only benign `WARNING: Using insecure random
number generator` (test-key RNG, not security-relevant).

## Config (from `run_bdec_e2e.sh`)

```
SP1_PROVER=cpu
SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
SHARD_SIZE=1048576
ELEMENT_THRESHOLD=67108864
HEIGHT_THRESHOLD=65536
TRACE_CHUNK_SLOTS=2
RAYON_NUM_THREADS=8
CARGO_TARGET_DIR=.build-cache.nosync   (iCloud-eviction safe)
driver: bdec_e2e_host (threaded, shared PLUM setup)
```

## Scope (honest)

One user `pk_U`. Two W3C-VC-style credentials from **distinct issuers**:

- **Cred1 (degree VC):** `A_1 = [type:UniversityDegreeCredential,
  issuer:did:web:waseda.jp, issuanceDate:2021-03-25,
  credentialSubject.{name:Takumi Otsuka, degree:Bachelor of Science,
  major:Computer Science, gradYear:2021, gpa:3.7}]`
- **Cred2 (employment VC):** `A_2 = [type:EmploymentCredential,
  issuer:did:web:acme.example, issuanceDate:2022-04-01,
  credentialSubject.{name:Takumi Otsuka, employer:Acme Corporation,
  role:Software Engineer}]`
- **Disclosed across both:** `A_down = [credentialSubject.gpa:3.7,
  credentialSubject.employer:Acme Corporation]`

SCOPE CAVEAT (verbatim from run): anonymous, unlinkable presentation of a
self-attested cross-issuer subset; **NOT** cryptographic selective
disclosure (`A_down ⊆ A` is not enforced; this is base BDEC).

## Results — all three relations accepted AND statement-bound

| Step | Relation | `accepted` | `statement_bound` | prove_ms | min |
|---|---|---|---|---|---|
| 4a | CreGen (issue degree VC) | `true` | `true` | 3 968 221 | **66.14** |
| 4b | CreGen (issue employment VC) | `true` | `true` | 3 935 254 | **65.59** |
| 6  | **ShowCre k=2** (disclose across both, same key) | `true` | `true` | 7 676 241 | **127.94** |

Total proving = 259.67 min (~4.33 h); build + overhead ≈ 7.4 min.

`statement_bound=true` = the guest committed its public statement to the
journal and the host recovered it and matched it against the input:

- CreGen commits `x_cre = (c, h, ppk)`, keeps `w_cre = (pk_U, psk)` private.
- ShowCre commits `x_show = ((ppk_TA)_j, ppk_UV, h_UV)`, keeps the shown
  credential `c_{U,V}` (= `show_sig`) **private** (Option B, matching the
  manuscript's witness modeling of `c_{U,V}`; see
  `03-preliminaries.tex:492` and the anonymity proof).

## What this closes

- **ShowCre statement-binding is now demonstrated** (step 6), closing the
  "presentation relation not yet statement-bound / showing side open" gap
  that the CreGen sweep left. Both credential relations now bind their
  public statement; a showing receipt certifies *which* statement was
  evaluated, not merely "k+2 signatures verify under some witness".
- **Full BDEC flow demonstrated end-to-end**: two cross-issuer issuances
  plus one k=2 anonymous cross-issuer showing, all statement-bound, on SP1.

## What this is NOT

- **Not ZK-wrapped.** These are succinct core STARK proves; they are not
  zero-knowledge (SP1 default `.run()` path). The ZK-wrap axis is separate
  and measured elsewhere (PLUM-verify wrapped 46.83 min; ShowCre k=1
  wrapped). The k=2 ShowCre wrap and CreGen wrap were **not** run here
  (Operator scoped this run to core jbind only, 2026-07-11).
- **Not cryptographic selective disclosure** (see scope caveat).

Raw log: `e2e_k2_run.log` (lines 379–389 = the three proves + RC).
