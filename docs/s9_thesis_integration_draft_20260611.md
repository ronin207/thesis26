# S9 integration draft — HELD for operator review (2026-06-11)

The CreGen and ShowCre k=1 succinct proves both completed at λ=80 on SP1
(`docs/measurements/pub_hardening_20260611/SUMMARY.txt`). This changes the
evidence base of the thesis's central claim, so the edits below are proposed,
not applied.

## What the result changes

1. **The scope caveat dissolves.** The dual obstruction's resource and ZK
   prongs were measured at the standalone verification and extended to the
   credential relations a fortiori. Both BDEC relations now have measured
   succinct receipts (26.98 min / 40.15 min, accepted, within 24 GB). The
   "cheapest relation" clause in the abstract and the a-fortiori sentence in
   contribution 2 can be replaced by direct statement: the credential
   relations themselves prove; what they produce is still not zero-knowledge,
   and the ZK wrap remains the wall.
2. **Contribution 2 strengthens and simplifies**: "Neither BDEC relation
   yields a zero-knowledge proof" stays true, but now reads as a measured
   contrast: succinct receipts of both relations exist (this work, measured);
   zero-knowledge versions of those receipts do not (wrap OOM, pairing-only
   inventory).
3. **The RISC Zero anomaly demotes further**: CreGen proves cleanly on SP1,
   so the anomaly is now a substrate-specific observation with no bearing on
   whether the relation is provable.
4. **Contribution 1's firstness extends**: first prove-mode receipts of the
   BDEC credential relations (CreGen and ShowCre) inside a general-purpose
   zkVM, beside the existing standalone-verify claim.

## Proposed edits (apply after review)

- **Abstract** (`main.tex:115`): replace "These walls are measured at the
  standalone verification, the cheapest relation in the credential system,
  and every BDEC relation contains it" with: "The credential relations
  themselves prove within the envelope: credential generation in 27 minutes
  and a one-credential presentation in 40 minutes, as succinct receipts that
  carry no zero-knowledge guarantee. The wall is therefore not the base
  proof but the zero-knowledge wrap" (exact wording to operator taste).
- **01-intro contribution 1**: add the two prove figures to the frontier
  measurements sentence; extend the firstness clause.
- **01-intro contribution 2**: replace the a-fortiori construction with the
  measured contrast; keep the wrap-OOM datum as the binding constraint.
- **06-evaluation**: new rows in the BDEC table (prove column: CreGen
  26.98 min / ShowCre k=1 40.15 min, proof sizes, peak RSS, single runs,
  documented tuning, cite pub_hardening_20260611); rewrite the "ShowCre is
  bounded by the wrap frontier" passage — the succinct base proof is now
  measured, only the wrap remains bounded.
- **055-security zk-gap section**: the resource prong's evidence upgrades
  from "standalone receipt + a-fortiori" to "both credential relations
  measured"; the PLONK-wrap OOM stays as measured at standalone scope, with
  the wrap-of-CreGen untested (note: its input receipt is 282 MiB, so the
  wrap can only be harder; this single a-fortiori survives, now one level
  up).
- **07/08**: feasibility sentences gain "including both BDEC relations";
  future-work drops "prove the credential relations" (done), keeps the ZK
  wrap and the PLUM-static harness.

## Honesty constraints to carry into the edits

- Single runs, documented tuning, cold start; same-night per-cycle rate is
  consistent with the S3 Loquat cold run, but Cell 2's archived 32.53 min is
  slow relative to tonight's rate. DO NOT quote a CreGen/Cell-2 wall-clock
  ratio until the S5 repeats settle Cell 2's day-to-day spread; cycle-level
  statements (1.94x Cell 2) remain safe.
- Receipts are succinct core STARKs, NOT ZK; nothing here touches the
  obstruction's ZK prong except to strengthen its evidence base.
- ShowCre measured at k=1 only; k=2 execute-mode anchor exists, prove does
  not.
