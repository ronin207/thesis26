# Cell 1 (emulated Griffin, no precompile) EXECUTE re-measure — post-standard-Griffin

**Why:** the manuscript's 56.4× cycle ratio (and the 7.08e9 Cell-1 figure) were computed on
the PRE-standard-Griffin (non-MDS) build. Cell 2/Cell 3 were re-measured in
`master_batch_20260706`; Cell 1 was not (its prove OOM'd, `cycles=NA`). This run supplies the
missing post-fix Cell-1 EXECUTE cycle count.

**Run:** `PLUM_HOST_MODE=execute PLUM_PROVE_ARM=emulated PLUM_SECURITY=80 plum_host`
(current standard-Griffin build). 2026-07-11, execute-only (memory-light, no OOM).

## Result
```
accepted=true  cycles=7,213,403,896  elapsed_ms=35304  syscalls=4,870,761
uint256_mul=4,870,761  griffin_fp192=0   (Cell 1: Griffin emulated, field via UINT256 emulation)
```

## Post-standard-Griffin execute-cycle anchors (all three cells now verified)
| cell | cycles | source |
|---|---|---|
| Cell 1 (no precompile, emulated) | **7,213,403,896** | this run |
| Cell 2 (Griffin precompile) | 123,372,417 | master_batch_20260706 (M5/C2) |
| Cell 3 (SHA-3 control) | 110,798,116 | master_batch_20260706 (C3) |

## Corrected ratios (superseding the pre-fix figures)
- **Cell 1 ÷ Cell 2 = 58.47× → 58.5×** (was 56.4× on the non-MDS build; precompile feasibility-recovery ratio).
- **Cell 1 ÷ Cell 3 = 65.11× → ~65×** (verification-level field-mismatch tax, software-Griffin vs SHA-3; was ~64× when using the pre-fix 7.08e9).
- (Per-multiplication tax 164× is a distinct measurement, unaffected.)

Manuscript updated: 56.4×→58.5× (04:52 ×2, 06:192/308/365/386, 08:19), 7.08e9→7.21e9 (06:271/277),
64×→65× (06:271).
