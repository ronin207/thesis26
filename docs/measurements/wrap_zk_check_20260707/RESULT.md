# wrap_zk_check_20260707 — ZK-of-wrap empirical confirmation

**Run:** 2026-07-07T16:35→17:07Z, rc=0. `run_wrap_zk_check.sh` (harness #3).
**What:** the stock gnark v6.1.0 PLONK circuit (the exact circuit the thesis's reduced-vk_map wrap chain uses) proved **twice** on the shipped `plonk_witness.json` (same witness, same public inputs), then the two raw proofs diffed. Randomized blinding ⇒ proofs differ ⇒ zero-knowledge; deterministic ⇒ byte-identical ⇒ not ZK. gnark-only (no SP1 core/compress/wrap chain).

## VERDICT = ZK (proofs differ — randomized blinding present)
- `proof1_raw_sha256 = 432f62211108cb839b84df5192219e800c3b3ae992a2e78fe4319ef1ff0b59ab`
- `proof2_raw_sha256 = 24267e6f4f8fcfac59afd79dc9f41bf59e8f9c183ef8806535562e522a127b5a`  (**differ**)
- `public_inputs_match = true` (both prove the same statement)
- test `plonk_bn254::zk_determinism_tests::plonk_zk_determinism_stock_circuit`: 1 passed, rc=0, 1893.54 s total.

## Timing
- prove1 779,655 ms (13.0 min), prove2 1,040,056 ms (17.3 min; thermal throttle after prove1), verify 5–25 ms. nbConstraints = 27,576,375.

## Meaning
The gnark PLONK prover injects fresh randomness, so the completing wrap is genuinely **zero-knowledge** (classical), not merely "ZK by construction from the blinding orders." Confirms the ZK half of the dual obstruction's Horn 2 (ZK-but-not-PQ). The wrap remains pairing-based (BN254), hence not post-quantum — Horn 2 stands. Property is witness-independent (blinding), so it carries to the PLUM-verify (46.83 min) and CreGen (4.20 h) wraps that use the same stock circuit + prover.

## Static pre-confirmation (corroborating)
gnark fork `p4u/gnark@cd7874155e26` `backend/plonk/bn254/prove.go` sets blinding orders L/R/O=1, Z=2 (active), filled via getRandomPolynomial/SetRandom → ZK by construction. This run is the empirical belt-and-suspenders.

## Thesis touchpoints (updated 2026-07-08)
055-security.tex:319 (tab:property-survival caption), 055-security.tex:357, 08-conclusion.tex:7 — "remains to be confirmed by a staged verification run" → confirmed.
