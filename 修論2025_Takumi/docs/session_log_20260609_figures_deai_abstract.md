# Session log — thesis figures, de-AI rewrite, abstract, ZK/OOM analysis

Saved 2026-06-09. This is a persistent record of the working session so it survives logout.
It lives in the thesis repo (iCloud-synced) so you can open it on any machine.

---

## What this session covered (in order)

1. **ZK / OOM question.** Whether omitting the zero-knowledge wrap (because it OOMs) amputates
   the thesis, what is actually being proved, and how to decompose the OOM into targeted runs.
2. **Lowering security to fit ZK in 24 GB**, and whether PLUM needs a non-Aurora zkSNARK.
3. **Running only parts of the AC algorithms inside the zkVM** (brainstorm — does it break
   process/security).
4. **Route B decision** — Aurora with zk enabled (native PQ+ZK, no pairing wrap).
5. **Three figures** assessed, corrected, and redrawn (two-provers, fmt-precompile, dual-obstruction).
6. **Captions** shortened across all figures and tables.
7. **Abstract** Sako-critiqued, then rewritten in plain voice (~253 readable words).
8. **Whole-thesis de-AI rewrite** removing the foreign AI tells while keeping the narrative connected.
9. **References** audited; `ref.bib` grew from 41 to 56 entries (15 web-verified additions).
10. **Figures restyled airy / box-free** with icooon-mono icons, matching a Sako-lab slide aesthetic.

---

## Central thesis findings (the load-bearing claims)

- **The dual obstruction.** The affordable proof is not zero-knowledge; the affordable ZK wrap
  (Groth16/PLONK over BN254, pairing-based) is not post-quantum. Either axis you fix, the other
  breaks under the 24 GB / target-hardware bound. This is the spine of the evaluation.
- **Inner vs outer prover layering.** STIR is PLUM's OWN inner signature IOP. Aurora / the zkVM is
  the OUTER prover — it proves PLUM.Verify's R1CS. The zkVM does NOT re-prove an Aurora proof.
  Do not label the outer system "Aurora/STIR".
- **Route B = Aurora with zk enabled** is PQ + ZK natively, no pairing wrap. The measured Aurora ran
  zk=false (Loquat / Fp127). PLUM-in-Aurora-Fp192 is not runnable on the current fp127-only harness.
- **R_static.** Aurora recompile ≈ 0.3 s (non-preprocessing); the wall-clock agility crossover does
  NOT hold vs Aurora. Fractal (preprocessing) R_static: Aurora ~µs vs Fractal 0.86–18.5 s (synth
  2^10–2^14), OOM ~33 min at BDEC 2^19. The flexibility advantage is CONDITIONAL on the preprocessing
  model — this rescues the claim, both-sides and non-curated.

---

## Build system (so a future session does not rediscover it)

- Pipeline: `platex` → dvi → `dvipdfmx`. latexmkrc sets
  `$latex='platex'; $bibtex='pbibtex'; $dvipdf='dvipdfmx %O -o %D %S'; $pdf_mode=3`.
- Build: `latexmk -g -interaction=nonstopmode main.tex`.
- **Image-embedding gotcha (was the big bug).** Per-package `[dvipdfmx]` is not enough — pgf/xcolor
  pulls in `dvips.def` afterward, the dvips driver wins, and `\includegraphics` emits emTeX
  `em: graph` specials that dvipdfmx silently ignores (0 images embedded). FIX: global driver option
  `\documentclass[dvipdfmx, a4j, 12pt]{article}`. Verify with `pdfimages -list main.pdf`.
- PNGs need `.xbb` bounding-box files: `extractbb figs/assets/*.png`.
- tikz needs `\usetikzlibrary{positioning,arrows.meta,shapes.geometric}` (shapes.geometric for any
  ellipse). pgfplots: `\usepackage{pgfplots}\pgfplotsset{compat=1.18}` (works under dvipdfmx).

---

## Figures — current state (all airy, box-free, icon-based)

- **§1 `fig:two-provers`** (01-intro.tex). Relation as plain bold floating text on top (no ellipse);
  CPU icon = Aurora (left), server icon = zkVM (right), italic floating notes, two diverging arrows.
- **§5 `fig:fmt-precompile`** (05-system.tex, §griffin-air). Two floating-text lanes (no boxes):
  top = multi-limb emulation → huge trace → DNF/OOM (1m45s); bottom = CPU icon + "syscall to native
  chip" → cross-table lookup (T1) → trace→receipt host-side cost.
- **§5.5 `fig:dual-obstruction`** (055-security.tex, §zk-gap). Certificate icon on the root receipt,
  two diverging paths: lock icon (not zero-knowledge) + memory icon (OOM ~20 GB / 24 GB) on one,
  shield icon (not post-quantum) on the other. Box-free fork.
- **§6 `fig:prove-time`** (06-evaluation.tex). pgfplots log-scale ybar: SHA-3 13.28 min, Griffin
  precompile 32.53 min, RISC Zero bigint 379 min; baseline DNF noted in caption.

Icons in `figs/assets/`: certificate, cpu, server, lock, memory, shield (256×256 RGBA) + `.xbb`.
(circuit.png was not downloaded; cpu is used for Aurora.)

Last verified build: **exit 0, 16 images embedded, 0 errors, 0 overfull >60pt, 0 undefined.**

---

## The 15 AI-tell taxonomy (the de-AI standard)

1 = X-not-Y antithesis, 2 = pivot connector, 3 = corrective redefinition, 4 = hollow emphasis adverbs,
5 = meta-significance flags, 6 = rule-of-three, 7 = balanced/mirror clauses, 8 = aphoristic closers,
9 = over-signposting, 10 = restatement padding, 11 = inflated vocab, 12 = vague quantifiers,
13 = "This + abstract noun", 14 = concessive throat-clearing, 15 = uniform rhythm.

**Keep #2, #6, #11, #14** (the Operator's natural register). **Remove the rest.** Do not over-correct
into uniform AI rhythm (#15 is the real risk of an over-zealous pass). No em-dashes (`---`) anywhere.

Preservation rule for any rewrite: keep all numbers, labels, refs, citations, math, captions, and
honesty caveats. Verified across rewrites by per-chapter digit-token diffs and label/ref/cite diffs
against `/tmp/thesis_prewrite/` snapshots (0 number changes, 0 ref changes).

---

## ref.bib additions (15, web-verified)

chaum1985, pointchevalsanders2016, sonnino2019coconut, bbs04, chase2017picnic, baum2021banquet,
desaintguilhem2021limbo, chiesa2020marlin, groth2016, gabizon2019plonk, fiatshamir1986,
grassi2023poseidon2, haback2022logup, w3cvc, fips206.

---

## Pending / standing offers (not started)

- **Experiment plans (Part A of the plan file).** Generate per-experiment OOM-aware plans (tuning
  ladder, abort thresholds, conclusion-impact) into `docs/experiment_plans/`. Runnable-as-is paths:
  RISC0 CreGen composite (`BDEC_PROVER_OPTS=composite`), Loquat-in-zkVM SP1 (`SCHEME=loquat MODE=prove`).
  Needs wiring: SP1 CreGen/ShowCre prove (mirror `plum_host.rs`). The workflow writes docs only; runs
  nothing. Note: `06-aurora-zk-enabled.md` (Route B) already drafted.
- **Security-game formatting (Part B).** Box the three AC games (unforgeability ~392, anonymity ~423,
  unlinkability ~469 in 03-preliminaries.tex) as Image-2-style boxed experiments, consistent with the
  signature EUF-CMA box. Keep proofs as prose sequence-of-games. No interaction diagrams (rejected as
  apparatus the claim does not need). Do not move simulators into definitions.
- **Commit.** The whole session body is uncommitted. Branch off master before committing (do not commit
  to master/main). Only when explicitly asked.
- **Visual confirmation.** Reopen `main.pdf` and check §1 / §5 / §5.5 / §6 render airy with icons sized
  and spaced right.

---

## Memory pointers (where the durable facts live)

- `~/.claude/projects/.../memory/MEMORY.md` — index.
- `thesis-writing-style-no-ai-tells.md` — the de-AI standard + voice sample.
- `thesis-framing-endorsed-2026-05-25.md` — what Sako actually endorsed (verbatim quotes).
- `thesis-precompile-framing-forced.md` — defensible core: quantified agility tax, slower-than-SHA-3
  inversion, dual-obstruction-as-instantiation.
- In-repo: `docs/thesis_journey_2025-07_to_2026-06.md` (chronological spine), `docs/r_static_finding_20260605.md`,
  `docs/thesis_coherence_audit_20260606.md`, `docs/thesis_defense_pivot_plan_20260605.md`.
