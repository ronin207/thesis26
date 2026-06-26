# Aurora with zero-knowledge enabled — the post-quantum + ZK route (Route B)

Preparation document. Read before running. This is the **highest-value cheap experiment**: it
demonstrates the one property the thesis says is hard — a proof that is *simultaneously*
post-quantum and zero-knowledge — on the substrate that can actually deliver it on a 24 GB
personal computer.

## Why this exists (the lever)

The post-quantum-vs-not question is a property of the **proof system**, not of PLUM's parameters.
The zkVM's only ZK wrap is Groth16/PLONK over BN254 — pairing-based, hence **not post-quantum at
any PLUM security level**; lowering PLUM's lambda only shrinks memory, it never makes that wrap PQ.
Aurora, by contrast, is transparent and hash/FRI-based (post-quantum under the QROM Fiat--Shamir
lift) and is **zero-knowledge-capable natively** — its ZK comes from the IOP itself, with **no
pairing wrap**. The measured Aurora baseline ran with **`zk=false`**. This run flips it on.

## Objective and conclusion-impact

**Question:** is a post-quantum AND zero-knowledge anonymous-credential proof achievable at all on
this hardware? The zkVM cannot produce one (the dual obstruction). Aurora can, in principle.

| Outcome | What it changes |
|---|---|
| **Completes (ZK proof produced)** | PQ + ZK anonymity is *demonstrated* in the static-circuit regime (for the Loquat-BDEC relation; PLUM-BDEC pending an Fp192 harness). The central finding sharpens from "anonymity not reached anywhere" to a **substrate contrast**: the static regime delivers PQ-ZK (at update-churn cost), the consumer-hardware zkVM does not. Update the proof-mode matrix `tab:proof-mode` (Aurora row: zero-knowledge = **yes**, not "zk=false"), the dual-obstruction figure/abstract (the obstruction becomes substrate-*relative*, not absolute), and the Section~7 decision rule. |
| **Completes but slow / larger** | Same qualitative result; report the ZK prove time and peak RSS as the static-ZK cost, contrasted with the zkVM's inability to produce one at all. |
| **OOM with zk on (unlikely)** | A static-ZK resource datum: even the PQ-native ZK route is bounded on 24 GB. This would be a surprise (the `zk=false` run fit in 3.78 min); record it. |

## Prerequisite (wiring)

- **v1 (runnable on the existing harness):** the libiop / Fp127 Aurora runner currently proves the
  Loquat-BDEC R1CS with zero-knowledge disabled. Enable it: in `scripts/fp127_aurora_runner.cpp`
  (and `.sh`), locate the Aurora SNARK parameter that toggles zero-knowledge (libiop's
  `aurora_snark` / `aurora_snark_parameters` carries a `make_zk` / zk boolean) and set it **true**.
  Same R1CS, same field; only the zk flag changes.
- **v2 (future, larger):** PLUM-BDEC over Aurora requires an Fp192 Aurora instantiation; the existing
  harness is Fp127-only. Out of scope for v1 — v1 demonstrates the *property* on the same harness
  you already measured.

## Exact command and starting config

Re-run the existing Aurora runner with the zk flag on, on the same Loquat-BDEC R1CS used for the
`zk=false` baseline (3.78 min). Pin the same security parameter as the baseline (achieved ~107.5
bits). `/usr/bin/time -l` for peak RSS.

```
# after setting make_zk = true in scripts/fp127_aurora_runner.cpp
cd "<repo>"
/usr/bin/time -l ./scripts/fp127_aurora_runner.sh   # (the zk-enabled build)
```

## Resource considerations (this is NOT a wrap)

Aurora's zero-knowledge is added by masking/randomisation polynomials in the IOP — a modest,
bounded overhead, **not** a Groth16/PLONK pairing wrap and **not** the recursion/SNARK-ification
that OOMs the zkVM. Expect prove time somewhat above 3.78 min and peak RSS modestly higher, with
**no OOM-class blowup expected**. There is no shard/segment ladder here; the only knob is the zk
flag and the security parameter (do not raise it chasing 128 in v1 — match the baseline so the
zk-on/zk-off comparison is clean).

## Watch and log

Prove time (vs 3.78 min `zk=false`), verify time, proof size, peak RSS, achieved security bits;
confirm the produced proof is the zero-knowledge variant (the flag took effect). Log under
`docs/measurements/<run>/`.

## Success / partial / abort criteria

- **Success:** a completed zero-knowledge Aurora proof of the BDEC R1CS -> PQ + ZK anonymity
  demonstrated in the static regime.
- **Partial:** completes at the achieved (~107.5-bit) level -> report as feasibility at that level
  (a feasibility probe, like the rest of the prove-mode measurements).
- **Abort:** hard time budget (it should finish in minutes; if it has not in, say, 1 h, stop and
  record).

## Recording

Add the `experiments.csv` row (Aurora, BDEC, `zk=true`). Update `tab:proof-mode` (Aurora row:
zero-knowledge yes), `fig:dual-obstruction` / the abstract (substrate-relative obstruction),
Section~6 (the PQ-ZK static datum), and the Section~7 decision rule (the static regime *can* deliver
PQ-ZK, at churn cost).

## Caveats to state with the result

- It demonstrates PQ-ZK for **Loquat-BDEC** (the same-scheme seam: not PLUM); PLUM/Aurora over Fp192
  is the natural follow-up and needs the Fp192 harness.
- "Post-quantum" rests on the QROM Fiat--Shamir lift — the thesis's open premise, same caveat as
  elsewhere.
- ~107.5-bit achieved is below the 128 target: a feasibility demonstration, not deployment security.
