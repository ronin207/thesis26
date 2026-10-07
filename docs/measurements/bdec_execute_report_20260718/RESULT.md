# BDEC execute-mode full report — reproduction run, 2026-07-18

Command: `cargo run --release --bin bdec_execute_report` (BDEC_HOST_SECURITY=80,
CARGO_TARGET_DIR=.build-cache.nosync, cold host build). Exit 0. Full log: run.log.
Purpose: demo-readiness check for the defense scenario (option 1: execute-only),
and reproduction of the thesis's execute-mode figures.

## Results (all arms accepted=true)

| Arm | total_instruction_count | GRIFFIN_FP192_PERMUTE | UINT256_MUL |
|---|---|---|---|
| CreGen, syscall | 289,221,111 | 13,206 | 137,971 |
| ShowCre k=1, syscall | 433,087,189 | 19,809 | 206,617 |
| ShowCre k=2, syscall | 575,089,654 | 26,412 | 275,134 |
| CreGen, emulated | 91,177,673,619 | — | 60,410,155 |
| ShowCre k=1, emulated | 136,457,778,261 | — | 90,614,893 |
| ShowCre k=2, emulated | 182,345,511,969 | — | 120,819,502 |

## Reproduction status

- Emulated counts reproduce the thesis conclusion's figures EXACTLY:
  9.12e10 (CreGen), 1.36e11 (ShowCre k=1), 1.82e11 (ShowCre k=2).
- Griffin syscall counts are exactly 6,603 x (number of PLUM verifications):
  CreGen = 2 verifs = 13,206; ShowCre k = k+2 verifs (19,809 / 26,412).
  This is the census answer to "why 6,603 per verification vs 1,052 standalone"
  (credential-relation verification includes the Merkle/pseudonym hashing the
  standalone verify does not).
- Additive model: ShowCre(k=2) - ShowCre(k=1) = 4.59e10 ~= ShowCre(k=1) - CreGen
  = 4.53e10 emulated instructions per additional credential.
- Emulation blow-up: ~315x instructions (all three relations, consistent).

## Demo note

For a LIVE demo, `BDEC_REPORT_ARMS=syscall` runs only the three fast arms
(~1-2 min each); the emulated arms are the hour-scale part and can be cited
from this record instead.
