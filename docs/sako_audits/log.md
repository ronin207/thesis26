# Sako-avatar audit log (/kazuesako-paper-review)

## Audit 1 — 2026-06-10, 修論2025_Takumi/ @ 9975fde+dirty (post-restructure working tree)
Mode: formative.
1. 🔴 NEW main.tex:97 — title claims the agility-tax thesis; document's central finding is the dual obstruction; title term not earned.
2. 🔴 NEW main.tex:115 — credential-level conclusion stated flat from standalone-signature evidence; a-fortiori inference not at point of claim.
3. 🔴 NEW 06-evaluation.tex:295 — tab:loquat-substrate 55.93 min carries no memory-configuration disclosure; defaults known to OOM, actual setting unrecorded.
4. 🔴 NEW (cross-chapter) — dual obstruction narrated at full length in 7+ places; anomaly disclaimer similar.
5. 🟡 NEW 02-related.tex:56 — chapter gap statement crowns per-change deployment cost; central finding mid-sentence only.
6. 🟡 NEW main.tex:115 — 32.5-min sentence is a three-qualifier clause chain; closing sentence dangles in different register.
7. 🟡 NEW 01-intro.tex §1.1 — no concrete decision-maker for the substrate choice; §7's framework audience never named in motivation.
8. 🟡 NEW 04-theoretical/06-evaluation — N_src, N_audit defined and promised in prose, values never given.
9. 🟢 NEW main.tex:115 — "a frontier result with a clear sign": sign of which axis, term before definition.
Verdict: not yet. Title decision + substrate-table settings provenance first.

### Resolution pass — 2026-06-10 evening (same day)
1 RESOLVED (title -> "Locating the Deployability Wall for Post-Quantum Anonymous Credentials in General-Purpose zkVMs"). 2 RESOLVED in prose (cheapest-relation clause in abstract) + measurement queued (SP1 BDEC CreGen/ShowCre prove mode added to hosts, S9; CreGen 243M cyc ~1.9x Cell 2 -> first credential-level prove attempt at real lambda=80). 3 IN PROGRESS (S2/S3 running; table rebuild on completion). 4 RESOLVED (08 double-telling -> once + pointer; 07 wrap inventory -> pointer; 06 anomaly echoes tightened; a-fortiori once in 055 + once in Limitations). 5 RESOLVED (gap = deployability wall; churn secondary). 6 RESOLVED (abstract rewritten, short declaratives, dangling sentence removed). 7 RESOLVED (university-consortium operator named in §1.1). 8 RESOLVED (N_src/N_audit prose added; tab:churn signature-swap zkVM row corrected to >=1* per §4 carve-out — found and fixed a table/§4 contradiction in the process). 9 RESOLVED ("clear sign" removed). Build clean.
- Audit-1 finding 3 RESOLVED 2026-06-10 21:55: S2+S3 archived (pub_hardening_20260610, n=3 per leg); tab:aurora-ref = mean+range of 3; tab:loquat-substrate = 44-64 min range, 405 MiB core proof, settings cited; ratio 12-17x (13.8x at means) replaces ~15x everywhere; 2026-06-09 unarchived numbers voided in SUMMARY.txt.
- Audit-1 finding 2 NOW MEASURABLY CLOSEABLE 2026-06-11 01:18: S9 proved BOTH BDEC relations at lambda=80 on SP1 (CreGen 26.98 min / ShowCre k=1 40.15 min, succinct NOT ZK, accepted, pub_hardening_20260611). Integration draft HELD for operator: docs/s9_thesis_integration_draft_20260611.md. Caution: no cross-day wall-clock ratios until S5 repeats (Cell 2's May figure slow vs tonight's per-cycle rate).

## Audit 2 — 2026-06-11, ~/Downloads/draft.pptx (progress-update deck, 14 slides)
Mode: formative.
1. 🔴 NEW s6 — research question is the OLD goal (reduce prove time via precompile); thesis claim is now the deployability wall; title/RQ/thesis tell different stories.
2. 🔴 NEW s9-s11 — per-stage blow-up tables, hex Merkle roots, "~10^12 rows", "native Aurora 67s k=14", "RISC0 ~9h/~18GB" match NO archived measurement; unsourceable numbers.
3. 🔴 NEW s9-s11 — primitive is "Poseidon" throughout; the built chip is Griffin-Fp192 on SP1; s11 recommends RISC0-over-SP1, contradicting what was done.
4. 🔴 NEW s10 — "Poseidon precompile would cut prove time roughly in half" states the cycle-cost prediction the thesis FALSIFIED (2.45x inversion) as the plan.
5. 🔴 NEW s6 — "~130 min ShowCre" projection contradicted by S9 measurement (40.15 min, 2026-06-11); also "9hr" projection stale.
6. 🔴 NEW (whole deck) — contribution-visibility: no slide shows what the student built/measured; no S2/S3/S9 results, no dual obstruction, no T2 proof.
7. 🟡 NEW s12 — uses "SNARK-friendly" (rejected term, 2026-05-25) and "Precompile Paradox" (rejected ornate framing); inversion content right, numbers unaligned with measured values.
8. 🟡 NEW s4-s5 — policy-change (GPA range) motivation contradicts the thesis's own scoping: policy at fixed structure is verifier-side, forces no recompile; use a STRUCTURE/scheme change instead.
9. 🟡 NEW s7 — "Cycle count ≈ proving time" contradicts the thesis's trace-area model (its own headline finding).
10. 🟡 NEW s13 — BN254/k≈4 mixed into the Loquat/Aurora mismatch story; Aurora is configured to match Fp127^2 (slide says so itself, then prices BN254).
11. 🟢 NEW s6 — wall-of-paragraph slide; her ついていけなさ pacing concern.
Verdict: not yet — rebuild content on the current verified state; arc can stay.

## Audit 3 — 2026-06-11, ~/Downloads/draft_v2.pptx (arrangement pass, post-repair)
Mode: formative. Arrangement-only.
1. RESOLVED in v2 — TOC(s2)/agenda(s3) told the flow twice; agenda now pure progress recap, 目次 owns the flow.
2. 🟡 OPEN — four Background slides (4-7) in a 10+5+10 format; suggest merging the static-circuit caption slide and the structure-change callout slide (4->3).
3. ✓ presented arc matches 目次 1:1 (she audits against the deck's own TOC); backups after plan; unsourceable trio hidden at end.
Verdict: arrangement sound after dedup; pacing of the background block is the one open item.
- Audit 3 extension 2026-06-11 (multi-level, draft_v2.pptx final): L1 number lockstep 12/12 canonical values present, 0 stale values on visible slides; L2 目次 extended to 6 sections (残された課題 added) matching slides 1:1; L3 spell-outs applied (zkVM/R1CS/OOM), asks added to plan; L4 one em-dash fixed. New slides: Four Contributions One Deep Dive (pos 9), Open Items As the Draft States It (pos 13). OPEN: background block still 4 slides (operator reworked them in PowerPoint; merge is theirs).

## Audit 4 — 2026-06-12, ~/Downloads/修論進捗報告20260616_大塚.pptx (post-fix-batch) vs 修論2025_Takumi/ @ working tree
Mode: deadline (seminar 6/16).
1. 🔴 NEW s9 vs thesis — deck claims SP1 BDEC prove numbers (CreGen 26.98 / ShowCre 40.15) that the compiled thesis denies (05-system:14-15 "did not yield a receipt"/"not attempted"; abstract: walls measured at standalone, "cheapest relation"); S9 integration draft HELD unapplied.
2. 🔴 NEW s11 vs 055-security:146 — deck theorem puts e_ZK in the unforgeability bound; thesis eq:adv-unf is EUF+KS+AIR only; e_ZK belongs to the anonymity bound (with e_sZK), which the slide omits — and that bound carries the wall story.
3. 🔴 NEW (process) — authorship inversion: load-bearing slide text is the reviewer-agent's register (s7 restored from agent transcript, not thesis sentences); the s11 error is the signature of editing formal content without owning the reduction. Operator self-retell protocol prescribed.
4. 🟡 RECURRING (audit 3 #2, 2nd) — background block still 4 slides; presented flow 14 vs 9-12 norm.
5. 🟡 NEW register sweep (counted) — 4 titles share one appositive template (s8, s12, s13, s18); 2 antithesis content lines (s10 takeaway, s15 — s15's introduced by the 6/12 fix itself). X→Y rewrites supplied.
6. 🟡 NEW s9 — thesis fig4 (log-scale bars incl. DNF baseline) absent from deck; measured slide is text-only; doubles as her summary-figure-before-今後の課題. Post-S9-integration, thesis fig1/fig4 captions need re-derivation.
7. 🟢 NEW s7 — problem/RQ text is agent paraphrase; thesis's own sentences (§1.5 "asks whether… answers: not yet"; abstract "We locate where the wall sits and what would move it") are plainer and drift-proof.
Verdict: not yet — (1) decide the S9 integration before the 16th and (2) fix the s11 theorem; both are deck-says-what-the-thesis-doesn't failures she reads in one pass.

### Audit 4 resolution pass — 2026-06-12 (same day)
2 RESOLVED — s11 live math now states BOTH thesis bounds: unf ≤ EUF+KS+AIR (stray e_ZK fragment blanked) and anon ≤ e_ZK+e_sZK (cloned eq placed after the anonymity prose). Verified in the PP-resave XML. NOTE: the OMML *fallback images* are stale (still show ⟸) in non-PowerPoint renderers until the Operator edits/saves s11 once in PP; PP itself renders the live math.
5 RESOLVED — titles: s8 'Contributions', s12 'Where the Wall Sits', s13 'Open Items', s18 'Backup: The Proving Pipeline'; s10 takeaway and s15 antithesis lines replaced with causal phrasing.
7 RESOLVED — s7 RQ box = thesis §1.5 sentences verbatim; body trimmed to mechanism (duplicate "We ask whether" removed).
6 PARTIAL — fig4 chart rebuilt as PNG + 16 icooon-mono icons delivered on hidden ASSETS slide 24 (drag-and-drop palette); placement is the Operator's. Thesis fig1/fig4 caption re-derivation still queued behind the S9 integration decision.
1 OPEN (Operator) — S9 integration decision. 3 OPEN (Operator) — six retellings: ~/Downloads/retellings_20260616.md. 4 OPEN (Operator) — background merge.
Watch loop armed: deck mtime in docs/sako_audits/watch_state.txt, text baseline in deck_snapshot.txt; on change → diff → avatar re-audit (changed slides vs thesis) → append here.

## Audit 5 — 2026-06-12, 06-evaluation.tex + 07-discussion.tex vs coverabstract @ working tree
Mode: formative (submission 7/20; seminar 6/16 colors priorities).
1. 🔴 RECURRING×3 (audit-1 #2 → audit-4 #1 → now; non-engagement escalation) — S9 (SP1 CreGen 26.98 / ShowCre 40.15 prove) still unintegrated: abstract stakes the wall on "the cheapest relation" a-fortiori, tab:bdec shows only the RISC Zero anomaly + execute, deck claims the measured numbers. Fix must be the reframe (in or out), not another local edit.
2. 🔴 NEW abstract vs 06:114 — abstract narrates TWO Cell-1 failure modes (OOM at defaults; >3h DNF under tuning); tab:plum-verify delivers one (OOM ≈1m45s, settings unstated). The 3-hour-tuned datum appears nowhere in §6.
3. 🔴 NEW 06:259/282/303 — "Achieved security 107.5 bits (target 128)" vs "same security setting" λ=80 in tab:loquat-substrate: two security notions (signature λ vs proof-system soundness) under one word; SP1 leg's soundness bits never stated. Her definition-demand: 107.5 bits of what?
4. 🟡 NEW (defensibility) — "feasibility is reached" / "viable" carries no operational criterion anywhere (Wu AQ7 open question still open); the wall verdict is binary and survives, but the base-proof "feasible" needs its one-line operational sense at point of claim.
5. 🟡 NEW 06:903-906 — the 2.45× inversion (central falsified prediction) is single-run with admitted 1.44× thermal noise nearby; §6 itself says "read with caution until repeated". S5 Cell-2/3 repeats are the one measurement between now and defensible.
6. 🟡 REGRESSED (audit-1 #4 class) — the wrap-kill/tension narrated 3× within §6 (frontier 475-499, ShowCre para 618-626, scorecard 876-885) + §7.1; "strengthens but does not instantiate" appears twice near-verbatim (490-495, 881-883).
7. 🟡 NEW 06:163-220 — ssec:headline interleaves the result with the κ-calibration block (190-220, the 19μs/2.6-cycles accounting); results-vs-model interleaving is the main blur source. Move calibration to ssec:costmodel, leave result + sign-postdiction pointer.
8. 🟢 NEW 06:384 — stray lowercase fragment " a per-component split ... would sharpen this." (leftover note).
9. 🟢 NEW 06:116/126 — the † on the SHA-3 row's λ=80 footnotes information already in the cell; all rows are 80.
Verdict: not yet — items 1 (decide, reframe) and 5 (run S5 repeats) are what separate this from defensible; items 3 and 2 are the cross-checks she lands in the first ten minutes. Abstract otherwise anchors cleanly.

### Audit 5 measurement closure — 2026-06-12 (campaign, bounded stages)
F5 PARTIALLY CLOSED, REFRAMED — inversion SIGN defended (Griffin arm slower in both same-session repeats, 17.80/17.82 vs 15.86/16.43 min) but the 2.45x MAGNITUDE did not reproduce: same-session ratio 1.10x; May Cell-2 (32.53) is 1.83x tonight's, outside thermal envelope, drift unattributed. The thesis's 32.53/13.28/2.45x anchors and the κ calibration (19μs/cell, 2.6 cyc/cell) are stale against current code state → Operator decision: re-anchor on tonight's runs vs keep May + disclose drift. Deck slides 9/10 carry 2.45x and 32.5/13.3 — same decision applies.
F2 CLOSED — Cell 1 under documented tuning passed the 3-hour mark still running (CHECKPOINT_3H 11:18); uncapped run continues for the true outcome. NEW SUSPECT: "OOM at defaults ~3 min" (May) needs one true-defaults re-run (queued post-Cell-1) — same drift concern.
Settings-skepticism CLOSED — S4: shard knob flat (17.3-17.5 min across 2^21-2^23), 12 threads fits and is faster (15.36 min); documented tuning is conservative, not favourable.
NEW CLAIM MEASURED — prove-mode additive linearity: CreGen n=2 (27-31 min), ShowCre k=1 n=2 (mean 42.2), k=2 58.14 vs 56.26 predicted (+3.3%); retires §6.6's prove-mode extrapolation caveat. Full table: docs/measurements/audit5_campaign_20260612/SUMMARY.txt.
Deck watch: 1 save, binary-only (fallback regeneration); no content change.
- 2026-06-12 13:25 — Cell-1 uncapped killed by Operator at 5h07m (still proving; datum upgraded: DNF within FIVE hours under tuning, current build). True-defaults re-check cancelled pre-start. Both rerunnable standalone IFF same build state; no ratio claim involves them, so no full-suite rerun needed.
- 2026-06-12 15:05 — S1 (Aurora ZK ENABLED, the never-run measurement) COMPLETED: ACCEPT, 22.94 min prove (6.1x the zk=false 3.76 min), verify 41.8 s, proof 856 KiB (+24%), peak RSS 9.17 GiB, achieved 107.5-bit. The security-deployability tension's static-side premise is now measured: the PQ-ZK proof EXISTS on this hardware via the static circuit and is still faster than the zkVM's non-ZK leg. Thesis touchpoints when integrating: fig1 caption ("in principle" -> measured), tab:proof-mode Aurora row/footnote-dagger, §6.3 aurora-ref, §6.5 frontier reading, §7.1 tension, abstract's Aurora clause. n=1 — repeats advisable alongside the held re-anchor/S9 decisions.

### Workflow edit batch — 2026-06-13 00:25-00:40 (wf_97127077-101) + ripple fixes
APPLIED to thesis: audit-5 findings 4 (feasible defined in ssec:eq), 6 (tension dedup), 7 (calibration block moved to ssec:costmodel), 8 (orphan deleted), 9 (dagger removed); Cell-1 tuned 5h07m datum placed after tab:plum-verify; S1 ZK-Aurora integrated (aurora-ref paragraph, tab:proof-mode new row + rewritten footnote, scorecard substrate-specificity sentence, fig:two-provers caption + node, 07-discussion scoping sentence, 055 zk-gap scoping, abstract one new sentence). Lockstep thesis-vs-records: 16 checks, zero mismatches. Verifier found 4 ripple sites the batch missed; fixed inline 00:55: 03-preliminaries:331 (both modes now stated), 08-conclusion:19 (zk-enabled counterpart acknowledged), Loquat/single-run qualifiers at 01-intro caption+node, 07-discussion, 055-security; 06-evaluation:333 Also-legitimate reading updated. Flagged-for-Operator sentences (veto-able): the feasible definition, the "binding resource is time" Cell-1 clause, the abstract sentence, the substrate-specificity sentences — all quoted in workflow report w4hfst003.
DECK NUMBER DEBT (lockstep, for the rebuild): expected stale (anchor-gated): 2.45x/32.5/13.3 on s9/s10(/s12/s18). New decision-independent corrections: s18 "OOM ~3 min" misattributed (that figure is Cell-2-at-defaults; Cell 1 row is OOM 1m45s); s9/s18 "no precompile: OOM" superseded (tuned Cell-1 = DNF >=5h NO OOM); s9 "no PQ-ZK proof on this machine" falsified by S1 (rescope to substrate like s12 or add the 22.9-min datum); s9 BDEC singles -> n=2 ranges (27-31, 40-44) + k=2 58.14 missing; s12 "27-40min" -> 27-44; s10 110/826K/7500x unverifiable against records (literature values; need source labels).
CAUTION: workflow agents ran latexmk at ~00:31 DURING S1 ZK repeat 2 (started 00:24) — repeat 2 wall-clock carries possible contention; weigh repeat 3 higher or run a clean repeat 4 if elevated.
- 2026-06-13 01:30 — S1 n=3 complete: prover mean 1317.7 s (21.96 min, range 21.43-22.94), proof 876,768 B identical x3, RSS 9.2-11.0 GiB, all ACCEPT; ZK premium 5.8x at means. Repeat-2 contention immaterial (came in faster). 06-evaluation aurora-ref updated to n=3 + premium 5.8x; SIX prose sites still say "22.9 minutes" (abstract, 01-intro caption+node, 07-discussion, 055-security, 03-preliminaries, 08-conclusion) — Operator choice pending: keep 22.9 (slowest-of-three, conservative) vs "about 22 minutes (mean of three)". Deferred build run post-measurement: exit 0, 93 pages, 0 undefined refs.
- 2026-06-13 02:05 — deck decision-independent factual corrections applied + gate-verified: s9 wall claim substrate-scoped + static 22-min datum added; BDEC singles -> n=2 ranges + k=2 58.1; s12 27-44; s18 OOM~3min misattribution fixed (defaults OOM / tuned DNF >=5h); s9 KPI "OOM" -> "DNF". Anchor trio (32.5/13.3/2.45x) deliberately untouched pending Operator decision. Story/goal slides untouched (Operator's).

### Workflow wecyy9t0v (2026-06-13 ~13:50) — PARTIAL: 3 fable agents failed (model-resolution: 'fable' not resolvable as workflow subagent override), repaired in main loop.
SUCCEEDED (Opus/Sonnet): prose propagation — 22.9->n=3 ("about 22 min, mean of three, 21.4-22.9") across abstract/01-intro/055/07/03-prelim/08; inversion softened to sign-robust in 01-intro:71 + 08-conclusion:9; S9 clause added to abstract; fig4_prove_times_v2.png created. Build clean.
FAILED then DONE IN MAIN LOOP (Fable 5): 06-evaluation.tex — honest-reading inversion now sign-robust + June repeats (17.81/16.15, n=2) with build-drift attribution; tab:plum-verify footnote adds June figures (May stays calibrated reference); kappa block gets provenance sentence (calibrated on May, June confirms sign, constants not re-derived); threats caveat updated (n=2 repeats, sign robust, magnitude range); tab:bdec now carries SP1 succinct BDEC proves (CreGen 26.98/31.11, ShowCre k=1 40.15/44.24, k=2 58.14, all NOT-ZK) + caption with k=2 additive-model 3.3% agreement; scorecard leftover 22.9->n=3. Scaffold written to ~/Downloads/firstslide_scaffold_20260613.md (2 candidate goal sentences from Operator's own §1.1/§1.5 + retelling template). Build exit 0, 93pp, 0 undefined refs. Coherence+lockstep re-verify running (wmzf84dyt, Opus/Sonnet, no fable).
OPERATOR VETO QUEUE (prose agent's authored sentences): abstract S9 clause incl. interpretive tail "so the wall is the zero-knowledge wrap rather than the base proof"; the two inversion-reframe sentences (01-intro:71, 08-conclusion:9); "across the May builds" label nuance; "All runs achieve 107.5-bit". Plus my 06-evaluation authored sentences (sign-robust honest-reading, tab:bdec caption).
DECK HANDOFF (PowerPoint was OPEN — Operator edits these themselves): slides 9/10 "2.45x" -> sign-robust "1.1x-2.45x (build-sensitive); sign robust"; s9 BDEC singles already corrected to ranges earlier; new chart at deck_icons/fig4_prove_times_v2.png to drag in; consider adding June 17.8/16.0 beside May.
- 2026-06-13 ~14:10 — coherence re-verify (wmzf84dyt, Opus/Sonnet) PASSED 5/6 checks; 1 real leftover fixed: tab:proof-mode Aurora-ZK row 22.9->"~22 min (n=3)", and SP1 BDEC succinct rows (CreGen 27-31, ShowCre k=1,2 40-58) added so the "every proof mode attempted" matrix is honest. Lockstep: only benign note (Cell3 reported as mean 16.15 not both runs 15.86/16.43 — intentional). Rebuild exit 0, 94 pages (was 93; +1 from the added tab:proof-mode rows / tab:bdec growth), 0 undefined refs. Thesis now fully consistent: S9 integrated, inversion sign-robust everywhere, 32.5 calibrated reference intact, Aurora ZK n=3 everywhere. All decision-independent + recommended-decision work COMPLETE.
- 2026-06-13 14:30 — DECK edits applied + gate-verified + PDF-confirmed: (1) NEW hook slide at position 3 ("Three Problems Demanding a New Kind of Credential") — 3 icon cards (fraud ~36k fake degrees / privacy LinkedIn ~700M / quantum clock), accent synthesis bar, cited [2] BDEC; built ONLY from Operator's own §1.1 motivation; answers Sako gate-3 (motivation-from-outside before mechanism). (2) sign-robust framing on slides 9/10 (now 10/11 after insert): KPI0 + Takeaway + "SHA-3 wins" all changed from bare 2.45x to "sign robust; 1.1-2.45x build-sensitive". Page numbers auto-renumbered (slide-number fields). 25 slides total (21 visible). Save-gate PASS, PDF render confirms hook slide + shifted measurement slide. Snapshot/state updated. NOTE for Operator: hook slide sits under the "Background" agenda item; consider relabeling agenda item 1 -> "Motivation & Background" for the 1:1 audit. Backup /tmp/deck_20260612/pre_hook_backup.pptx.
- 2026-06-13 15:05 — PRIMARY-SOURCE citations added (slide 3 + thesis §1.1). Found via BDEC's own refs + web-verified: fake degrees=SCMP 2021 (Manav Bharti); deportations=BBC News 2023 (Brijesh Mishra/Jalandhar scam); LinkedIn=Nixon Peabody 2021; PQ=NIST FIPS 204/205 (already in bib). ref.bib += scmp2021manavbharti, bbc2023canada, nixon2021linkedin; §1.1 inline-cited each clause (BDEC kept as survey cite); thesis built 95pp, 0 undefined. Slide 3: inline source tags per card + full source line replacing bare [2]. PRECISION FIXES applied both: LinkedIn "breach exposed"->"data scrape put...up for sale" (LinkedIn disputes breach); deportations kept number-free (BDEC's 150 undercounts; ~700 better-sourced). Save-gate PASS, PDF-confirmed. Snapshot/state current.
- 2026-06-13 15:40 — §1 REFRAME (BDEC = use case, substrate study = contribution): Operator caught that §1.1 mirrored BDEC's intro (same 3 examples/order/arc -> derivative + motivating BDEC's contribution not the thesis's; same root as the gate-1 deck stop). FIXED: §1.1 rewritten to 3 paras leading with the deployment/substrate question, fraud examples compressed to one cited clause (breaks BDEC's three-example arc), explicit "BDEC-PLUM is the use case; the comparison of proving substrates is the contribution." Grounded: every claim cited (scmp/bbc/nixon for fraud, fips204/205 for PQ migration, jeudy+BDEC emerging, Aurora cryptoeprint:2018/828, zkVM cryptoeprint:2023/1032+bruestle+yang2026sokzkvm SoK, PLUM). Independent Opus adversarial check PASSED all 5 gates (mirror-broken, framing-correct, all 12 cites resolve, clean handoff to 1.2-1.4, register clean); fixed the one "not X but Y" pivot it flagged. Thesis built 95pp, 0 undefined. DECK aligned: problem-statement slide (8) RQ box += "BDEC-PLUM is the use case; the comparison of proving substrates is the contribution." Save-gate PASS (working file 2.27MB intact, 25 slides, all media; 944KB scratch was PP media recompression, not loss). PDF-confirmed. Snapshot/state current.
- 2026-06-13 18:00 — Wake reconcile: deck content UNCHANGED vs 15:40 (the 42-line "diff" was page-number field caches recomputed +1 by the PP in-place save during the security investigation; fields render correct regardless). Security slide 12 verified back to clean 9-shape state (overlay add+revert was net-zero). Snapshot/state regenerated. 25 slides, structure intact.
  OPEN (Operator-pending, NOT watcher items):
  (A) Security-slide gap: I found LibreOffice MISRENDERS slide 12's OOXML math (draws ≤ as ⟸, drops the anon equation) — my prior renders/“fixed” claims were against a lying tool. XML is correct (3 ≤, 0 ⟸). Asked Operator: viewing in PP or PDF? and is the gap the arrow / missing anon-equation / whitespace? Awaiting answer. Fix ready: sec_bounds.png (both bounds, renderer-independent image) to drop in. DO NOT declare fixed again without a PowerPoint-native (not LibreOffice) verification.
  (B) Constructed a rigorous PQ-ZK-survival proof for BDEC-in-zkVM (weakest-link soundness + terminal-layer ZK; iff theorem; dual-obstruction corollary; Aurora-ZK witness; generalizes §5's T1-T4). Offered to typeset into §5 + run an adversarial proof-checker panel. Awaiting Operator go.
- 2026-06-13 ~17:30 — INDEPENDENT STATUS VERIFY (wf_a8ec1415, Opus+Sonnet, fresh): THESIS all-present — latexmk exit 0, 95pp, 0 undefined refs/cites; §1.1 use-case reframe verbatim; 3 primary cites in bib+inline+resolve in bbl; S9 tab:bdec rows w/ not-ZK label; inversion sign-robust (4× "2.45" all range-framed, no bare assertion); Aurora ZK n=3 everywhere, no leftover single-run. DECK all-present — hook slide pos3 w/ inline [SCMP/BBC/Nixon] tags; problem-statement use-case line verbatim; measurement sign-robust + BDEC n=2 ranges + k=2 58.1; 25 slides.
  SECURITY SLIDE 12 (the open worry) — XML now CONFIRMED correct AND complete: ⟸ count = 0, ≤ count = 3 (all in OMML), anonymity bound Adv^anon ≤ e_ZK + e_sZK PRESENT in live math alongside the unforgeability bound. So in PowerPoint it should render correct+complete. SOLE remaining uncertainty: PowerPoint visual display cannot be verified headlessly (LibreOffice misrenders OOXML); Operator must eyeball slide 12 in PowerPoint. If it shows wrong there, drop in sec_bounds.png. Item (A) downgraded from "broken" to "verify-in-PP".
- 2026-06-13 18:50 — DECK CHANGED (Operator, 25->27 slides): added "The Real-World Rigidity Crisis" hook (e-passport SNDL, crypto-hardware e-waste, $7.1B White House PQC migration) — strong rigidity-angle motivation, aligns with the real thesis. kazuesako-model audit:
  🔴 (1) DUPLICATE: slides 3 AND 4 are identical "Real-World Rigidity Crisis" — delete one. (2) THREE UNCITED CLAIMS (she fact-checks): $7.1B — VERIFIED, US OMB Report to Congress on PQC migration, 2024 ($7.1B federal civilian 2025-2035, mandated by Quantum Computing Cybersecurity Preparedness Act 2022); SNDL — standard NIST/NSA "harvest-now-decrypt-later" concept; e-waste/crypto-agility — weakest-sourced, needs a cite or softening.
  🟡 (3) Operator HID the "Three Problems" fraud hook (now slide 5 hidden) and led with rigidity — good alignment, but now agenda (still 6 items, still NO goal sentence on slide 2) doesn't name the rigidity hook; the two hooks motivate different needs (rigidity->agility/substrate=contribution; fraud->anonymity). (4) hidden != deleted before Slack.
  GATE-1 still open: no goal sentence on slide 2. PowerPoint OPEN -> did NOT edit. Offer ready: dedupe slide 4 + add [OMB 2024]/[NIST]/cite-or-soften when PP closed. Snapshot/state reconciled to 27.
- 2026-06-13 19:10 — Rigidity-crisis slide (3) CITATIONS added (real-world, non-BDEC), gate-verified + PDF-confirmed: bullet1 [NSA/CISA/NIST]; bullet2 [OMB 2024; crypto-agility reports]; bullet3 [U.S. OMB 2024]; + sources footer (OMB Report to Congress 2024 / NSA CNSA 2.0 / industry crypto-agility). CORRECTION to prior log: slides 3&4 are NOT duplicates — slide 4 ("Dynamic Identity in Practice") is an EMPTY title-only stub the Operator created; flagged for Operator (fill or delete; blank slide in flow is a Sako risk). Softest cite = the e-waste claim (industry/crypto-agility, not government) — Operator may soften "massive e-waste" or keep w/ industry cite. Gate-1 still open (no goal sentence on slide 2). Snapshot/state -> 27-slide cited state.

## Audit 6 — 2026-06-13 ~19:30, full-deck multi-agent (wf_d067a7ce, 5 section agents + synth, visual+text)
Mode: deadline. Deck now 27 slides (Operator added slide 4 "Dynamic Identity in Practice" + slide 5 "Performance Tax and the Precompile Paradox").
BLOCKING:
1. 🔴 NEW — HIDDEN slides 24-26 carry FABRICATED numbers (Poseidon ~90K cyc, k=14, ~9h/480x, hex Merkle roots, ~10^12 rows, 2.4M constraints, Poseidon-128) contradicting the thesis's Griffin/Fp192/λ=80/Cell1-DNF facts and SHIP in the .pptx → delete 24-26 (and 27 assets palette) before any Slack post. NB Operator earlier chose "keep hidden trio" — this RE-ESCALATES given they're fabricated + contradictory.
2. 🔴 RECURRING (gate-1, Nth time) — no goal sentence on slides 1-2 before mechanism.
3. 🔴 RECURRING — agenda↔slide broken: "Background" = 7 slides (3-9); slides 3-5 unannounced.
4. 🔴 RECURRING (repetition) — slides 6-9 four identical BDEC actor diagrams, one idea over four figures → compress to 2.
5. 🔴 NEW — slide 5 title "Precompile Paradox" = rejected ornate term → rename plainly.
6. 🔴 NEW — slide 4 "Dynamic Identity in Practice" EMPTY (title only) → fill or delete.
7. 🔴 NEW (visual) — slide 3 body placeholder shares title's box geometry (per python-pptx); MY render showed it lays out OK → Operator verify in PowerPoint.
SHOULD-FIX:
8. 🟡 NEW — slide 5 SCOPE ERROR: anchors cost to 127-bit Loquat ("emulate 127-bit math in 31-bit arch") = mismatch (A) PLUM already SOLVED; thesis studies mismatch (B) 192-bit→BabyBear. Switch to PLUM 192-bit/~7 limbs + Griffin.
9. 🟡 NEW — slides 12/13: May 32.5/13.3 reads as single-session 2.45x; add same-session June 17.81/16.15=1.10x labels.
10. 🟡 NEW — slide 12: Aurora 3.76 (zk-disabled) vs 22 min (zk-enabled) conflatable → annotate "zk-disabled" on the 3.76 row.
VERDICT: not ready — fix gate-1 goal sentence + DELETE hidden fabricated slides first; rest downstream.
- 2026-06-13 ~20:00 — Operator applied fixes (PP OPEN, I did NOT edit). RESOLVED: audit-6 #1 (3 fabricated hidden slides 24-26 DELETED; 27→24 slides, assets palette remains hidden) and #6 (slide 4 "Dynamic Identity in Practice" now FILLED with the GPA-change rigidity scenario + Zcash NU5 example). Zcash claim VERIFIED accurate (Sapling trusted-setup ceremonies; Orchard/NU5 2022 = Halo2, full circuit rewrite) → cite Electric Coin Company NU5 blog (2022). STILL OPEN: #2 gate-1 goal sentence (slides 1-2), #3 agenda↔slide (3-5 unannounced; slide 4 now a real motivation slide → add "Motivation" agenda item), #4 background 6-9 repetition (4 identical diagrams → cut to 2), #5 slide-5 "Paradox" rejected term, #8 slide-5 scope (still 127-bit, should be 192-bit PLUM). NEW: slide 4 Zcash claim needs the ECC citation. Mechanical batch queued for PP-close: slide4 Zcash cite, slide5 rename+127→192, slide12/13 May/June labels + zk-disabled annotation, delete assets palette.
- 2026-06-13 20:20 — DECK FIX BATCH applied (wf_e8ad49d2, 1 serial writer + 3 parallel verify, all PASS) + save-gate PASS (2.3MB, raw-XML edits did NOT poison): slide4 Zcash cite [Electric Coin Company, NU5 2022] + sources footer (NU5 verified real); slide5 retitled "The Field-Mismatch Cost" (Paradox removed) + scope fixed 127-bit→"192-bit (≈7 BabyBear limbs)" + "PLUM's 192-bit prime field"; slide12 KPI0 += "(May calibrated ref; same-session June 17.81/16.15=1.10x)" + Aurora row "3.76 min (zk-disabled)"; slide13 already sign-robust (no change); ASSETS palette slide deleted (24→23 slides). Lockstep: 0 "Paradox", 0 "127-bit", 0 fabricated. Snapshot/state reconciled to 23.
  MINOR: slide4 inline [ECC NU5 2022] clipped in render (pre-existing body-placeholder overflow; bottom Sources line attributes it regardless) — verify in PP. slide5 phrasing "required by PLUM's 192-bit prime field" slightly awkward — Operator may smooth.
  REMAINING (Operator-only, the 6/16 gate): gate-1 goal sentence (slides 1-2), agenda restructure (add "Motivation" for slides 3-5), compress Background 6-9 to ~2.

## Audit 7 — 2026-06-14, SPINE-ONLY (trilemma deck arc, gate-1/gate-2/three-sentence)
Mode: formative (auditing the proposed narrative arc, not a rendered file).
Object = BDEC-PLUM substrate comparison; trilemma (flexible/PQ/private; pick two on a laptop) = proposed spine visual.
GATE-1: PASS-with-conditions. Goal IS one sentence (the centre-question); axis must be NAMED on S2/S3 before any result; zkVM correctly framed as means (a substrate position), not goal.
GATE-2: PASS. Trilemma is a legitimate framing of the finding, NOT a finding-dressed-as-goal — PROVIDED the open centre is the question and the edge-placements are the deliverable. Risk: object(BDEC-PLUM use case) vs probe(the 4 cells) vs finding(the empty centre) must stay distinct on S3.
THREE-SENTENCE: PASS-with-one-clause — the "flexible = re-audit footprint not wall-clock" definition is a load-bearing subordinate clause; if it is not ON the triangle the slide is wrong (matches the standing 'flexible' definitional risk).
Findings: (1) gate-1 axis-naming on S2/S3 [RECURRING from audits 5/6 — goal sentence still the standing item]; (2) S3 must label the FLEXIBLE corner with its re-audit-footprint definition or the spine is unsound; (3) "pick two" title vs centre-is-open must not contradict (two-of-three is the finding, centre-empty is the question — keep them one story); (4) proxy + λ=80 + single-run + none-is-ZK caveats must be legible on S3, not deferred to backups.
VERDICT: spine is sound and bringable IF S2/S3 name the comparison axis and define FLEXIBLE on the triangle. The arc passes the model.

## Audit 8 — 2026-06-14, TRILEMMA SLIDE BUILD + DECK RE-TUNE (single-writer + parallel-verify)
Mode: deadline. Built the flexible/PQ/private trilemma as a real matplotlib graphic and integrated it as the spine visual.
BUILD LOOP (wf_d360a53c, 24 agents, 4 rounds + spine audit): render -> 4-gate Sako panel (goal/means, ontology, settings-honesty, presentation) -> refine -> re-render. Did NOT auto-converge; the render agent kept failing the SAME blocker (slide opened with the result not the goal; empty centre faint; R_static missing; FLEXIBLE def too small). Supervisor took the pen and rebuilt the script (docs/sako_audits/trilemma/make_final.py).
CONFIRM PASS (wf_4ff8b979, 4-gate panel on the rebuild): 1 blocking (red slash cut through "ALL THREE @ 24 GB" text -> reads as crossed-out words) + 6 should-fix. Applied: slash removed -> dashed EMPTY ellipse + "UNREACHED" label; means/goal line added; props:/measured: labels (property-vs-probe survives without colour); demoted favourable 17.8 to footnote; centre = inference (PLONK OOM measured) vs open (no PQ-ZK wrap). Polish (conditional-PQ hollow tick, prose density) deferred. CONVERGED by supervisor gate-check.
INTEGRATION (python-pptx, single serial writer, verified): trilemma full-bleed at position 3 (slide size 13.33x7.5 == PNG, pixel-exact); goal-question on S2 + "Motivation & the Trilemma" agenda item; Background compressed 4->2 (deleted slide7.xml=static-circuit build + slide9.xml=re-derive prose, kept slide6=intro + slide8=KeyGen rigidity bind); DROPPED dead orphan slide24.xml (ASSETS palette, unreferenced -> would have caused duplicate-name corruption). Live deck 23->22 slides; valid zip (no dup names), python-pptx reopens, 22-page LibreOffice render all clean. Backups: /tmp/deck_backups/ pretune (23sl) + posttune (22sl).
WHOLE-DECK VERIFY (wf_beae3d3e, 3-lens panel): deck_pass=TRUE, 0 blocking. Agenda 1:1 OK, front-flow OK, Background compression coherent (S7->S8 stand alone, no dangling ref to deleted builds), no stale "(slide N)" refs (page nums are auto slidenum fields, auto-renumbered). 2 should-fix + polish, all on EXISTING slides:
  - S14 Wall closed only 2 of 3 corners (PQ+ZK empty, FLEXIBLE silent) -> FIXED: appended green line "Flexibility — the third corner — is reached on both substrates (the update-churn re-audit footprint); what stays empty is post-quantum and zero-knowledge together." Rendered, no overflow, Page auto-renumbered to 14. Copied to live + verified.
  - S14 number presentation (32.5 verify vs 27-31/40-44 BDEC vs 6h19m): NOT wrong (verify vs BDEC relations, internally consistent) -> reported, not changed.
POLISH (Operator-optional, reported not applied): S9 echo "flexible" to keep triad alive S2->S3->S9->S14; S10 reorder so measured-comparison leads and precompile follows (precompile-as-headline trap); S5 GPA threshold (verified 4.5, matches S3/S8 — non-issue); S6 agenda-label tightness.
FINAL STATE: live deck 22 slides, md5 1bf61a30, snapshot+watch_state regenerated. Backups in /tmp/deck_backups (pretune 23sl, posttune 22sl, posttune_v2_wallfix). Trilemma PNG+script in docs/sako_audits/trilemma/.

## Audit 9 — 2026-06-14, FRONT REBUILD + Griffin/FreeLunch finding (deck_pass after 3 rounds)
Driver: this session's research (motivation-evidence sweep, ePrint relevance audit, completeness sweep, Griffin/FreeLunch margin check). Front rebuilt to the need→question→gap→method→results arc.
CHANGES (live deck now 27 total / 24 visible, md5 c52ba27e):
- NEW S3 "The Need" — verified non-BDEC motivation (NIST/EU PQ mandate; eIDAS-unlinkability + BBS-not-PQ; FibRace/Ethereum consumer-HW); keyword heads, no em-dashes. Replaced weak OMB/$7.1B/e-waste opener.
- S4 = pure-tension FRAMING trilemma (open centre, NO numbers/verdict) [was the numbered substrate trilemma].
- S5 Problem: cut "and answers: not yet" → goal lands as an open question.
- NEW S6 = gap MATRIX (Argo/Policharla/CAPSS/This × PQ/ZK/general-purpose-zkVM/measured-HW). This-thesis ZK cell = "the wall (located)", NOT a green check (matches the dual obstruction; resolves a self-contradiction vs S15/16). "SNARK-friendly" removed (CAPSS row = "algebraic-hash PQ sigs").
- NEW S10 Methodology — "Built (this thesis): Griffin-Fp192 precompile…" visually dominant.
- S15 = numbered substrate trilemma MOVED into results (before Wall); 32.5 anchor now carries "(n=2, build-sens.) λ=80" + footer "thermal variance ≤1.44×".
- S17 Open Items + S18 Plan: FreeLunch open-item added.
- HIDDEN/demoted: old Rigidity + Dynamic-Identity slides (weak evidence); NEW Griffin/FreeLunch Q&A backup.
VERIFY (3 Sako-panel rounds): R1 wf_4a636529 → 4 blocking (findings-first S4/S5, prose-wall S3/S6, SNARK-friendly). R2 wf_4a96b952 → those fixed; 2 NEW blocking (matrix ZK self-contradiction vs S15/16; S15 missing point-of-claim caveat). R3 wf_e29a256f → **deck_pass=TRUE**. (R3 agent's "22min/garbled footer" was a 70-dpi OCR artifact; verified clean at 130 dpi.)
GRIFFIN/FREELUNCH MARGIN CHECK (wf_0110bd5b): verdict CANNOT-ESTABLISH-WITHOUT-ESTIMATOR — the 14-round count is sized vs the FGLM model FreeLunch beats; the instance actually broken is a 2^55 toy field (width 12); couples to premise T4. Detail: docs/gap_sweep_and_griffin_finding_20260614.md §5.
DOCS this session: motivation_evidence_20260614.md, eprint_relevance_audit_20260614.md, gap_sweep_and_griffin_finding_20260614.md. Graphics+scripts: docs/sako_audits/trilemma/ (make_framing.py, make_gap_matrix.py, make_final.py).
BACKUPS: /tmp/deck_backups/ {pre_frontrebuild, post_frontrebuild, round2, round3}.
OPEN (Operator): (1) 055-security.tex Option-B FreeLunch edit NOT yet applied (queued, awaiting go); (2) Option-A Poseidon2 migration is a construction decision for the advisor; (3) polish — S6 hard-codes "(slides 15-16)", re-verify before export; S3 colon-led (acceptable).

## Audit 10 — 2026-06-15, CLEANUP on the Operator's reworked deck
The Operator reworked the deck after Audit 9: rebuilt BOTH trilemmas as NATIVE pptx Venn slides (S4 = open question; S16 = substrate answer), converted the gap matrix to a NATIVE table titled "The Challenges" (S7), HID the old gap-matrix PNG (now S6); live deck = 25 total / 24 visible. Whole-deck visual read done; cleanups applied (single serial writer, verified):
- S7 "The Challenges" table: filled the 3 MISSING row labels (only "CAPSS (2025)." was present) → "Argo et al. (CCS 2024)", "Policharla et al. (2023)", "CAPSS (2025)", "This thesis (BDEC-PLUM)" (bold blue, highlighted row). Checkmark pattern already correct (Argo ✓✓✗✓ / Policharla ✓✗✗✓ / CAPSS ✓✓✗✗ / This-thesis ✓✗✓✓ — ZK=✗ = the wall, consistent with the dual obstruction).
- S16 retitled "Each substrate buys two, never three" (was a DUPLICATE of S4's title; now clearly the answer vs S4's question).
- S20 backup "zkVMs vs SNARK Circuit Compilers": stale "(slide 10)" → "(see the Inversion slide)".
- Em-dashes removed (no-em-dash style rule): S11 methodology, S17 Wall.
Live md5 ea67c35; snapshot+watch_state regenerated. Backup /tmp/deck_backups/修論進捗報告_20260615_pre_cleanup.pptx.
OPTIONAL (reported, not changed): "The Challenges" title is really a prior-work/gap table (could read "Where the field stops"); hidden S6 gap-matrix PNG now redundant with the S7 native table (harmless, left). STILL OPEN: 055-security.tex Option-B FreeLunch edit; eyeball in PowerPoint.

## Audit 11 — 2026-06-15, tri-audit (learner + security-researcher + grad-defence) on reordered deck @ 26 slides, then FIX PASS
Mode: formative. Ran three lenses on the front-half reorder + chart/de-dense work. Verdict was: present-ready after 2 blocking + ~4 should-fix labeling corrections; no claim is unsound. ALL applied + render-verified this session (serial writer, /tmp/deck_work12.pptx → live; backup /tmp/deck_backups/修論進捗報告_20260615_triaudit_fixes.pptx):
- 🔴→DONE S14 Inversion: de-densed to a native 3x3 table (Static-circuit vs zkVM × Griffin/SHA), green/red diagonal flip, limb gloss. Renders clean.
- 🔴→DONE S15 Security: led with the CONDITIONAL in the TITLE itself ("a conditional result (premises T1 lookup-binding and T2 AIR per-row still open)"); removed the overlapping banner (body is OMML math, could not be pushed down). Renders clean, no overlap.
- 🟡→DONE S13 Measured: native COLUMN_CLUSTERED chart; renamed "Griffin chip"→"PLUM + precompile"; removed the "(May calibrated…)" provenance note.
- 🟡→DONE S16 Venn-answer: added Aurora-corner caveat footnote (= Loquat-Fp127 proxy 107.5-bit; PLUM-in-Aurora not runnable; *post-quantum under hash-based STARK / QROM open). Clean bottom-left.
- 🟡→DONE S12 Contributions: flexibility-qualifier footnote (advantage is over PREPROCESSING SNARKs, not non-preprocessing Aurora); fixed doubled-"is" ("The result obtained is the advantage is"→"The advantage is a smaller re-audit footprint") and repeated "obstruction" (bullet 3). XML-verified.
- 🟡→DONE glosses: S5 BDEC/CreGen/ShowCre verbs gloss (repositioned to lower-left whitespace, clear of [2] citation); S8 PLUM/zkVM gloss (repositioned to left-middle, clear of citation).
- removed S7 premature "Aurora =" gloss (Aurora is not named in S7's body; it collided with the [24][25][4] citations).
Live: 26 slides, no duplicate zip parts. RESIDUALS (not blocking, reported to Operator): Measured KPI-box Aurora basis (22.0 bar vs the 3.76/44-64 callout) still reconcilable; forward-reference softening; zkVMs(S7) header "W" clip is a LibreOffice raster artifact (fine in PowerPoint); T3 label ("black-box PRF use") left as-is in OMML body. Did NOT mechanically re-run the 3-agent workflow a third time — each fix was render-verified slide-by-slide; offered a fresh confirmation tri-audit on request.

## Audit 12 — 2026-06-15, CONFIRMATION tri-audit (re-run after Audit-11 fixes) + POST-AUDIT FIX PASS
Multi-agent workflow (wf_8935912a, 36 agents): 4 lenses (learner / security[proof-checker] / defence /
consistency) over a fresh full render, every finding adversarially verified against the actual patched deck
(default-refute), then synthesised. VERDICT: **present-ready-after-fixes**. All 7 Audit-11 fixes HELD, ZERO
regressions; adversarial verify correctly REJECTED 10 findings incl. a re-flagged S12 doubled-"is" that does NOT
exist in the .pptx (XML-confirmed). 21 confirmed findings deduped to 1 blocking + 4 should-fix + polish.
APPLIED this session (live md5 88e83d16; backup /tmp/deck_backups/修論進捗報告_20260615_audit12_fixes.pptx);
all numbers re-verified against docs/four_scheme_benchmark.md before editing:
- 🔴 BLOCKING (S10 vs S14 vs S24 cycle units): RESOLVED. Ground truth — Cell 1 (no precompile) 7,082,608,888 cyc /
  1052 GRIFFIN_FP192_PERMUTE = 6.73M cyc/perm (= S14's "6.6M"); Cell 2 (with precompile) 125,504,123 cyc;
  Cell1÷Cell2 = 56.4×. Fixes: S10 "~2,000-3,000 cycles per permutation" (was the per-192-bit-MUL cost mislabeled)
  → "thousands of cycles per multiplication, millions per Griffin permutation when emulated (no precompile)";
  S14 6.6M cell tagged "(no precompile; 192-bit math in limbs)" so it is not read against the 125.5M with-precompile
  total. NOTE: the audit wrongly called S22's 56× an "orphan/underivable" — it IS sourced (Cell1/Cell2 execute;
  DNF is the PROVE, not the execute cycles). Kept + anchored, did not drop.
- 🟡 S13 Aurora reconciliation: caption "12-17× per-proof gap" → "12-17× substrate gap (zk-disabled core); the
  chart's ~22 min Aurora bar is the zk-ENABLED PQ-ZK proof" — the 3.76 (zk-disabled) vs 22 (zk-enabled) configs
  now explicit.
- 🟡 S14 SHA row: static cell → "~826,000 R1CS / hash (SHA-256)", zkVM cell → "native ops + precompile (SHA-3)";
  + "λ=80" added to the takeaway 32.5/13.3 figures.
- 🟡 S9 column: "General-purpose zkVM" (a MEANS scored as a desideratum = gate-3 circular) → "Flexible
  (late-binding)", aligning the gap table's axes with the deck's own trilemma (Flexible/PQ/Private) + consumer-HW;
  scoring unchanged (Argo ✓✓✗✓ / Policharla ✓✗✗✓ / CAPSS ✓✓✗✗ / This ✓✗✓✓); reading-note gained a "Flexible=" gloss
  + "achieved via a general-purpose zkVM". COHERENCE WIN (now matches S4/S16 axes). FLAG for Operator: this reframes
  the novelty axis from substrate to desideratum — revert if the novelty claim must stay "first in a general-purpose zkVM".
- 🟡 S22 backup: "bespoke Griffin chip"→"Griffin-Fp192 precompile", "committed chip area"→"committed trace (AIR)
  area", 56× anchored "(Cell 1 7.08 B → Cell 2 125.5 M execute)".
DEFERRED (polish, by judgment): S13 on-bar inversion annotation (caption already states it + next slide is "The
Inversion"); S15 ZK-simulator learner gloss (S15 is OMML-dense/full, overlap risk > benefit); S16/S13 extra λ=80 ticks.
Render-verified S9/S10/S13/S14/S22 in LibreOffice. STILL OPEN (carried): hidden 25-26 fabricated-number purge before Slack.

## Audit 13 — 2026-06-15, REGISTER REALIGNMENT (deck prose/titles vs author's own voice + lab convention)
Trigger: Operator felt "the prose throughout my slides feels inconsistent with my work." Compared the deck against
primary sources: the author's THESIS (01-intro.tex), the author's OWN Dec-2025 progress deck
(~/Downloads/修論進捗報告20251222_Takumi Otsuka.pdf), and 5 lab decks (/tmp/style_compare/{mizuno,kawahara,morita,
kimura,wu}.txt). DIAGNOSIS (verified): English is NOT the issue (the author's Dec deck is already EN on the same
template); the issue is TITLE REGISTER DRIFT. Author's established register = plain FUNCTIONAL section-name titles
with punch confined to BODY taglines (Dec deck title "Background" + body tagline "Impractical at Scale"); thesis
subsections are functional ("The Hidden Cost: Cryptographic Rigidity"); all 5 lab decks use functional titles
(研究背景/研究目的/研究範囲と方法/今後の予定). The June deck had drifted to aphoristic/question titles
("A credential issued in 2026 must still be safe in 2036", "Can a proof be flexible...?", "Each substrate buys two,
never three", "Where the Wall Sits") — the felt inconsistency.
Ran a 41-agent workflow (wf_111b52ad): per-slide functional-title proposal + adversarial in-register/faithfulness
verify + synthesis. The verify caught a FACTUAL bug beyond register: the Audit-11 S15 title said "T2 AIR per-row
still open" — BACKWARDS; 055-security.tex:88-94 confirms per-row layer PROVEN, lookup-borne layer OPEN.
Operator chose (AskUserQuestion): full pass (titles + agenda + body prose); S3 = "Motivation".
APPLIED + verified (live md5 7c478c47; backup /tmp/deck_backups/修論進捗報告_20260615_register_remap.pptx):
- 13 TITLES → functional: S3 Motivation, S4 "The Deployment Requirements: Flexible, Post-Quantum, and Private",
  S6 "Background: Cryptographic Rigidity", S7 "Two Proving Substrates: zkVM and Static Circuit", S9 "The Current
  State of Post-Quantum Anonymous Credentials", S10 "The Field-Mismatch Tax", S11 "Artifact and Evaluation Setup",
  S13 "Evaluation: PLUM and BDEC on Consumer Hardware (M5 Pro, 24 GB)", S14 "Hash-Cost Inversion Across Substrates:
  Algebraic versus Bitwise Hashing", S15 "Security Preservation: a conditional result (lookup-borne premises open;
  per-row layer proven)" [FACTUAL FIX], S16 "The Three-Property Deployment Trade-off", S17 "The Deployability Wall:
  A Dual Obstruction to Post-Quantum Anonymity", S22/S24 functional.
- AGENDA (S2) rewritten 1:1: Motivation / Background / Problem Statement and Related Work / Approach and
  Contributions / Evaluation / Security and Discussion / Open Items and Plan (dropped "Trilemma"/"the Wall").
- Resolved the 3x "Background" title collision (S3→Motivation, S5 Background, S6 Background: Cryptographic Rigidity).
- BODY PROSE consistency: defined terms verbatim ("deployability wall" S8/S9/S13/S15, "field-mismatch tax" S10);
  removed ALL-CAPS shouting (S10 MEASURES/BUILDS, S14 CHEAP/EXPENSIVE in takeaway — table CHEAP/SLOW callouts kept);
  removed "X, not Y" antithesis (S9 "not a failure of the goal"→"and the goal still stands"; S16 corner labels
  "X, not Y"→"Y not reached"); "attack it"→"absorb it" (S10); S23 "Open, honestly:"/"Claim, proven:"→"Open (T2):"/
  "Proven:"; S14 speaker-note provenance reconciled (R1CS/cycles published, 32.5/13.3 measured); S16 "cost is
  assurance"→"the cost is update churn".
- Deliberately NOT changed: S12 "per-substrate obstruction" (a deliberate rescoping per pub-hardening, NOT a slip);
  did not add new tagline textboxes (bodies already carry the demoted ideas in their own closing lines — avoids
  overlap + repetition). LibreOffice renders went stale mid-batch; all edits file-verified via a:t extraction.

## Audit 14 — 2026-06-15, CLARITY/STORY pass (Operator: "content prose not intuitive; S3/11/12 unclear, S10/18 too many")
Operator's meta-critique was correct: prior audits optimized gates/claims/numbers/register, never "is this bullet
list clear and parallel to read." Surfaced + applied (live md5 5d9ac640; backup …_clarity_story.pptx):
- S3 Motivation: ran a 6-agent web-research sweep (wf_7f8a6374) for a stronger, non-repeating story. VERIFIED-verbatim
  facts now anchor it: BBS "not post-quantum secure" (IETF draft-irtf-cfrg-bbs-10 §6.9, 2026-01); EUDI ARF v1.4
  "Full unlinkability" = even colluding issuer+verifier cannot link (2025-03, Art 5a(16)); No Phone Home campaign
  (ACLU/EFF/Schneier, 2025); FibRace 3 GB mobile RAM floor (arXiv 2510.14693). Rewrote S3 to 3 one-line property-led
  needs (Post-quantum / Private+unlinkable / On the holder's device) + a 3-part pincer punchline; the flowing
  narrative moved to SPEAKER NOTES (matches the lab's narrate-the-background convention; Wu/Kawahara open 研究背景
  from an external situation). CAVEATS (unverified, kept off-slide): CNSA 2.0 dates (defense.gov 403), NIST IR 8547
  exact figures (via PQShield), NSM-10 2035, Bootle KB count.
- S10 Field-Mismatch Tax: cut the background bullet ("industry moves to zkVMs") and the vague "not equivalent
  environments for PQC" meta-caveat; kept the mismatch + the precompile/cost; now 2 focused bullets.
- S11 → "Evaluation Setup"; removed the "Built…" line (it duplicated S12's Artifact).
- S12 Contributions: 4 PARALLEL noun-led bullets mirroring the thesis's 4 contributions, RESTORING the missing one
  (Artifact+measurements / The deployability wall / A falsified prediction + cost model / Update churn).
- S18 Open Items: 6 scattered items → 3 grouped+prioritized (Security premises open / Implementation, disclosed /
  Measurement hygiene).
OPEN for Operator: (1) S3↔S4 "three" mismatch — S3's needs = {PQ, private, on-device}; S4's trilemma = {flexible,
PQ, private} with on-device as the setting. Recommend signposting S4 as the reframe (flexible enters as the
deployment-lifecycle need from S6). (2) S10 visual: field-mismatch (S10) and arithmetic-mismatch (S22) are ONE
phenomenon — S22 is the formal cost model behind S10's tax. Recommend a SIMPLE native limb-emulation visual on S10
(1 big op → ~7 limbs → ~k² limb-muls → millions/perm), keeping the Θ(k²) formal model in backup S22. Not yet built.
NOTE: /autoresearch is NOT a registered skill (Operator asked to run it when writing stories) — used a research
workflow instead; consider authoring the skill.

### Audit 14 follow-up — 2026-06-15: both OPEN items BUILT (live md5 aa663481)
- S10 limb-emulation VISUAL built natively (rounded rects + 7 limb boxes + right-arrows, no matplotlib): row A
  "one 192-bit value → 7 × 31-bit limbs → ≈49 limb multiplies → thousands of cycles"; row B red "one Griffin
  permutation → millions of cycles (emulated)" → green "with the precompile: one syscall → ~56× fewer cycles".
  Sits between the 2 bullets and the citations, no overlap. Formal Θ(k²) model stays in backup S22.
- S4 SIGNPOST line added under the title to close the S3↔S4 "three" seam: "On the holder's own device, the proving
  system itself faces a three-way trade-off: flexible, post-quantum, private. Only two are reachable at once." Makes
  the reframe explicit (S3 on-device need → S4 setting; flexible enters as the deployment-lifecycle property S6 elaborates).

### Audit 15 — 2026-06-16: narrative-introduction goal clarity (Gate 1 + three-sentence test), deadline mode (live md5 31973904)
Artifact: opening slides S3 (Background) + S4 (Problem Statement) of 修論進捗報告20260616_大塚.pptx.
- 🔴 NEW: S3 closing sentence was grammatically broken ("The question now is '…' is the open question." — doubled copula), and it was the goal sentence. REMOVED; S3 now ends declaratively on the gap ("…no scheme yet reaches all of these at once on the holder's own device.").
- 🔴 RECURRING (goal stated twice / Gate 1 means-in-goal): S3 asked the goal AND S4 re-asked it with the tool inside ("can a zkVM produce that ZK proof…?"). FIXED: the goal now appears ONCE, on S4 under "Research Question", tool-free — "Can a person prove, on their own device, that they hold a valid credential without revealing which one, with a proof that stays secure against a future quantum computer?" The means (PLUM/BDEC/zkVM/24 GB) follows as "Made concrete, …"; the binding-constraint paragraph is unchanged.
- 🟡 RECURRING (Audit 14 OPEN): the three-list seam (S3 needs {PQ, unlinkable, on-device} vs S5 trilemma {flexible, PQ, private}) remains; flexible still enters only at S5/S6. Reduced by dropping S4's competing "two things at once" enumeration. Not fully closed.
Verdict: passes Gate 1 and the three-sentence test now (goal one sentence + tool-free on S4; approach = PLUM-in-BDEC-in-zkVM; deliverable = characterize wall + specify masked zk-STARK). The remaining trilemma-seam is a should-fix, not a blocker. Brought to her: yes for the goal; flag the flexible-axis entry if she asks where "flexible" comes from.

### Audit 15 follow-up — 2026-06-16: closed the trilemma seam on S5 (live md5 see deck)
- 🟡→done: S5 line now motivates "flexible" inline and ties it to the deployment: "On the holder's own device, the proving system itself faces a three-way trade-off: flexible (it absorbs changes in standards or policy), post-quantum, and private. In practice, only two are reachable at once." Flexible no longer appears unmotivated relative to S3's need list {post-quantum, unlinkable, on-device}; it enters as a proving-system property forced by the deployment.
- Presenter notes UNCHANGED: S5 note already explains flexible-as-qualifier and "two of three"; S3/S4/S14 notes never list flexible, so none needed editing. (Considered a four-word S5-note opening tweak; rejected because it would create a subject mismatch with the note's next sentence.)
- Goal alignment now end-to-end: S3 need (PQ + private, on a device) → S4 goal stated once, tool-free → S5 trilemma with flexible motivated as the substrate axis → S7/S14 reuse the same three axes.

## 2026-06-20 — 修論発表.pptx (13-slide story deck, defence)
Mode: formative. Author edits present (trilemma→Venn-in-laptop, wall→underline headers).
- 🔴 1 [s3-4 vs s12] goal promises private(ZK)+PQ; s12 says ZK unreachable → deliverable contradicts goal, contribution invisible. NEW
- 🔴 2 [s10] 14.89min/18.67GB claimed with no λ/hardware/runs; λ=80 not 128, 128 doesn't fit. RECURRING (special-setting)
- 🔴 3 [s7-8 vs s9-12] visual weight inverted — background (tax,91%) heaviest figures, contribution (precompile,wall) text. NEW
- 🟡 4 [s9-10] PLUM undefined at first use. NEW
- 🟡 5 [s6] Venn lost thesis-position + which property is lost; Flexible* asterisk dangles; "Post Quantum" wraps. NEW
- 🟡 6 [s12] RISC-0 vs RISC Zero — one name. NEW
- 🟡 7 [s8,s10] DNF claim repeated. NEW
- 🟢 8 title only 修論発表; 9 bars wall-clock vs 1.13× cycles; 10 em-dash on s12
Verdict: not yet ready; fix goal-vs-deliverable (s4/s12) + disclose λ=80 (s10) first. Passes gate 3 (Bob).

## 2026-06-22 — flexibility-framing review + model rebuild from #discuss-zksnark
Mode: formative. Artifact: defence_story.md motivation + the "should flexibility be a thing" question. Mined from:@kazuesako in C0B0W4AB007 (May–Jun 2026); model updated (sako-operating-model.md §8).
- 🔴 1 [defence_story motivation] "flexibility" is a banned-class term by her own rule — 2026-05-11 (1778507992) "SNARK-friendly / zkVM-friendly are not scientific … avoid those vague words that blurs your goal." Same ban applies to "flexibility / general-purpose". NEW (evidence-backed).
- 🔴 2 [motivation→RQ seam] she names the disconnect herself — 2026-05-12 (1778513633) "I don't see the connection between the large goal and the specific problem." Confirms the seam flagged 2026-06-20 is RECURRING and hers, not invented.
- 🔴 3 [flexibility need] gate-3 unmet — 2026-05-19/05-20 she is not persuaded a signature-scheme update / security-parameter increase "would be expected to happen". The flexibility NEED is asserted, not shown. NEW.
- 🟡 4 [admissible form] her RQ template 2026-05-24 (1779609041): flexibility = name relation Rzz the SNARK can't prove but zkVM can, in minutes. Collision: R_static says Aurora recompiles in µs → no Rzz survives vs Aurora → axis empty in wall-clock; only unmeasured human cost remains, which the precompile re-incurs.
- note: Sako deputized Wu (2026-06-17) and has NOT herself endorsed any reframe; Wu's "forget BDEC, focus PLUM-in-zkVM + deployability wall" is Wu's, not hers.
Verdict: motivation fails her term-discipline gate as written. Two honest exits — (A) convert flexibility to the Rzz relation-coverage claim with minutes, or (B) retire the word and stand on feasibility + deployability wall. "Flexibility as an unmeasured virtue" does not pass the model. Author picks; the choice is framing and is his.

## 2026-06-23 — 055-security.tex (security preservation + T1–T4); deadline mode
Artifact: 修論2025_Takumi/055-security.tex (mature draft; PLUM-in-zkVM-BDEC conditional preservation thm + T1–T4 + dual-obstruction §zk-gap). Reviewed as input to a rewrite.
- 🔴 1 [:173–176 vs :360–371] RECURRING (3rd+ → non-engagement): anonymity bound Adv^anon ≤ ε_ZK+ε_sZK stated as preserved, then §zk-gap shows ε_ZK not achieved by produced receipt. Same goal-vs-deliverable contradiction as 2026-06-20 (s4/s12) + 2026-06-22. FIX must be theorem-level caveat at point of claim, not another distant paragraph.
- 🔴 2 [:86–94,:158–161,:238–266,:313–329] RECURRING (repetition-as-failure): T2 restated 4×, no load-bearing paragraph. FIX: keep :313–329 as THE T2 paragraph, reduce others to one-line pointers.
- 🟡 3 [:69–73] NEW: Pegasus (2025/1841) attribution — verify it proves (Q)ROM for power-residue PRF signature, not Legendre-only; narrow if not.
- 🟡 4 [:268–288] NEW: "8 of 10 rounds / 7 FreeLunch" attack figures need exact paper+table sourcing.
- 🟡 5 [:25–26,:362,:391] NEW (no-AI-tells, not a Sako gate): "X but not Y" antithesis ×3 → plain declaratives. Em-dashes: none in body (clean).
- 🟢 6 [:238] consistency: "premise T2" vs "premise (T2)"; "Habock/Al~Kindi" diacritics — sweep.
- 🟢 7 [fig :343–345] add λ=80 to dual-obstruction figure caption (disclosure at point of claim).
Verdict: NOT yet ready. Fix #1 (theorem-level) + #2 (consolidate T2) first; 3–7 continue. Gate 2 (ontology: instrument vs finding) and Gate 5 (settings disclosure) already pass. P1 needs: T2 premise, the :313–329 a-fortiori paragraph, ε_AIR + 2^-191 coverage figure.

### 2026-06-23 follow-up — #1 + #2 applied + gate
- #1 APPLIED (:176): anonymity bound now carries point-of-claim caveat (ε_ZK not realized by produced receipt; delivery settled negatively in §zk-gap). Recurring goal-vs-deliverable contradiction closed at theorem level.
- #2 APPLIED (:86–94): threat-model T2 paragraph trimmed to a pointer (B-family breakdown was a dup of :300–306). T2 now: brief in threat-model + theorem hypothesis (:158–161), canonical status (:238–266), measurement-reading (:313–329, distinct function). Repetition 4-heavy → 2-heavy+2-brief.
- Gate: #1+#2 (both RECURRING blockers) addressed. Remaining :238/:313 split is intentional (status vs measurement-reading), not repetition. Ref \ref{thm:security-preserve} valid. NOTE: PDF not rebuilt yet.
- Open queue: #3 Pegasus cite verify, #4 FreeLunch sourcing, #5 antithesis recast, #6 consistency sweep, #7 fig λ=80, then P1 prose.

### 2026-06-23 loop iter 1 — #6a + #7 applied; #5 surfaced
- #7 APPLIED (fig caption :354): added λ=80 + 24GB target at point of claim. Gate: passes settings-disclosure on the figure.
- #6a APPLIED (:238): "premise T2" → "premise (T2)". Diacritic part (Haböck/al-Kindi :367) deferred — needs ref.bib check.
- #5 SURFACED, not auto-applied: the three "X but not Y" sentences (:25–26 gap-from-toolchain-not-construction; :362 AoK-but-not-ZK; :391 Groth16-not-bad-generally-only-ruled-out-by-PQ-goal) are PRECISE technical/scoping contrasts, not rhetorical AI flourishes. Rewriting risks losing precision → Operator's taste call, flagged not changed.
- Next iter: #3/#4 citation verification (WebFetch eprints 2025/1841 + FreeLunch), #6 diacritic .bib check, then P1 technical prose.

### 2026-06-23 loop iter 2 — #3,#4 VERIFIED; #6 umlaut applied
- #3 Pegasus (2025/1841): VERIFIED accurate via title "Signatures from Sigma-Protocols for Power Residue PRFs with (Q)ROM Security" + same author group as PLUM. No change. Passes claims-vs-evidence.
- #4 FreeLunch/Resultant: VERIFIED. Resultant 2025/259 abstract: "8 out of 10 rounds of Griffin" + "most variants of Griffin fail to reach the claimed security level" (exact); "7 for FreeLunch" = previous-best (8-1), vault-corroborated. No change.
- #6 APPLIED (:367): Habock -> Hab\"{o}ck (matches bib haback2022logup). FLAG: "Al~Kindi" (nbsp->"Al Kindi") vs handle "al-Kindi"/"Al-Kindi" — Operator to confirm; bib l2beatzk howpublished has same issue, sweep if fixing.
- STATUS: all 055-security.tex Sako findings resolved/surfaced. Applied: #1,#2,#6umlaut,#7. Verified-no-change: #3,#4. Operator calls: #5 (antithesis = precise contrasts), Al-Kindi rendering.
- Next iter: P1 (cost-model + falsified-prediction) technical eval-section prose into a draft doc; surface for review (P1 is post-defence).

### 2026-06-23 loop iter 3 — REDIRECTED off P1 to Loquat remeasure (Operator chose (b))
- Built scripts/loquat_remeasure_rhostar.sh: forces fresh guest rebuild (drops stale elf-out) + execute sanity (--check), then PROVE at λ=80 with a tree-RSS tripwire at 22 GB (kills before 24 GB hard wall). Expect |U|=4096, ρ*=1/16, r=4.
- KEY RISK guarded: stale guest ELF (include_bytes!(env!(LOQUAT_VERIFY_ELF_PATH))) would silently re-run |U|=256. --check + cycle-count comparison verifies the fix is in the ELF.
- Run is Operator-launched (AFK; 16× prove hogs 24 GB). Loop repointed to WATCH for the result log and process it; P1 prose deferred.

### 2026-06-23 — citation verification from primary PDFs (Operator-provided 2024-347, 2025-259, 2025-1841)
- #3 Pegasus (2025/1841): FULLY VERIFIED. Abstract: "novel commit-and-open Σ-protocol based on the power residue PRFs" + "security proof of Pegasus in the quantum random oracle model (QROM)". Attribution exact, no change.
- #4 FreeLunch (2024/347): "7 out of 10 rounds of Griffin" verbatim. Practical Table 3 = (t,α)=(12,3) → α=3 (degree-3).
- #4 Resultant (2025/259): "8 out of 10 rounds of Griffin" + "lower than the claimed security level for all cases" verbatim. Practical apps α=3 (lines 893,1117,1215,1516 "α=t=3"); analyzes α∈{3,5}.
- 🔴 FACTUAL ERROR (055-security.tex :278-279): claims practical breaks are "degree-5 ... rather than our degree-3". FALSE — both papers' PRACTICAL Griffin breaks are α=3 (degree-3), SAME degree as thesis instance. Degree is NOT a safety margin; the real distinguishers are rounds (14 vs 7-8) + width (4 vs 12) + field (199-bit vs reduced/smaller). Dangerous false reassurance. SURFACED for Operator approval (security-argument call); section's broader no-128-bit-floor stance remains correct.

### 2026-06-24 loop (W4) — PQ-ZK reachability research
- VERDICT: ENGINEERING-blocked for a working MEASURED PQ-ZK proof by 7/20; crypto sound+favorable in principle; NOT fundamentally blocked. Everlasting/IT anonymity separately FUNDAMENTALLY open (standard-model statistically-hiding TRACE commitment).
- KEY UPDATE (corrects vault "unshipped"): VEIL shipped as crate slop-veil in SP1 v6.1.0 (2026-04-11, ~9760 lines) but UNWIRED — SDK exposes no zk()/veil() (prove.rs:281-296); panics on "multiple eval claims on same PCS commitment breaks ZK" (zk/inner/prover.rs:586-594), which the multi-shard prover does routinely = named wiring blocker.
- Decision-determining #: peak RAM of a masked VEIL-style ZK prove of PLUM-verify (non-ZK baseline 18.67GB resident, ~5.3GB headroom; VEIL +3% is TIME not RAM — mask-column RAM unmeasured by anyone).
- Minimal path: VEIL triples for PLUM-verify's dominant sumcheck/Basefold sub-protocol → measure RSS → if > headroom, layer Blendy (TCC2025 2025/1473, 120x less mem at <2x time).
- Corrections (primary-verify pending): round-LB = Haitner-Hoch-Reingold-Segev 2007/145 (not HNORV); non-int PQ SH commitment EXISTS at leaf (SIS) but blocked at TRACE recommit; QROM multi-round cite = Chiesa-Di-Hu-Zheng 2025/2166.
- Papers needing download (403): Hobbit 2025/1214 (runner-up decisive RAM#), LaBRADOR/Greyhound/LaZer, CMS 2019/834 + CDHZ 2025/2166 bounds, SIS-SH param (Libert EC2016), Haboeck-Kindi 2024/1037 degree budget.
- W1 build (bjygblzp7) still running; W4 measurement gated on build success.

### 2026-06-24 loop — W1 BUILD FIXED, prove running
- In-place fix WORKED: .build-cache.nosync (iCloud-excluded) + gnark-ffi build.rs provenance patch → clean compile (4m45s), phase 1 [ok] guest rebuilt + execute ran, phase 2 PROVE now live (pid running) at λ=80 |U|=4096. bjygblzp7 will notify on prove completion/OOM.
- Papers not yet in ~/Downloads (W4 lit-numbers pending).
- This iteration: W3 significance-evidence research launched (external need, not Operator framing).

### 2026-06-24 loop (W3) — significance evidence gathered → docs/significance_evidence_20260624.md
- 3 strongest hooks: (1) EU eIDAS 2.0 (Reg 2024/1183) wallet by Dec-2026; TS4 says "no existing ZKP approach mature enough" + BBS+ non-PQ = named decider w/ admitted open gap; (2) harvest-now-deanonymize-later for anonymity (Moran-Naor 2006; anchor ePrint 2025/1030 Lysyanskaya ASIACRYPT2025) — DEFENSIBLE FORM only (computationally-hiding-commitment transcripts); (3) EUDI TS13 mandates holder-device proving + Google Longfellow ~800ms/Pixel = external referent for AQ7 "practically acceptable".
- DEFENCE TRAP to pre-empt: Thaler/a16z + Slamanig ("ZK posted today is fine vs future QC") — reconcile via the computational-vs-statistical-hiding boundary (matches Operator 2026-06-17 checkpoint). Lead with the boundary, never a blanket claim.
- Boundary held: evidence only; Operator frames the motivation. Unverified sources flagged in the doc.
- W1 prove (bjygblzp7) status checked below.

### 2026-06-24 loop (W1) — REMEASURE COMPLETE (ρ*-fixed Loquat-verify)
- RESULT: SP1 Loquat-verify λ=80, |U|=4096, ρ*=1/16, r=4: prove_ms=5,336,874 (88.95 min); peak tree RSS 15,055 MB (~14.7 GB, NO OOM); execute 647,490,612 cyc. Log: docs/measurements/loquat_remeasure_rhostar_20260624_011512.log.
- vs old buggy |U|=256 (55.93 min): ρ*=1 bug UNDERSTATED the zkVM Loquat-verify prove by ~1.6×. (OOM fear did not materialize; 14.7GB < 24GB.)
- ⚠ CONSISTENCY: the Aurora arm (3.76 min) was emitted via emit_aurora_r1cs → ALSO uses loquat_setup, i.e. it is still at the OLD |U|=256. For an apples-to-apples PAPER-FAITHFUL substrate RATIO, the Aurora arm must be re-emitted+re-proved at |U|=4096 (bigger R1CS → slower, possible OOM). DIRECTION (static circuit faster) is robust regardless.
- THESIS EDIT TO MAKE (06-evaluation.tex tab:loquat-substrate, NOT auto-applied): either (a) report both arms at fixed ρ* (re-run Aurora), or (b) present the reduced-param common-mode ratio as before + add the ρ*-fixed zkVM absolute (88.95 min) with the caveat that the cross-substrate ratio is direction-only until Aurora is re-run.

### 2026-06-24 loop — P0-Aurora DEFERRED; W4 VEIL-wiring assessment launched
- Aurora-arm remeasure command found: `emit_aurora_r1cs --mode loquat-verify --security 80` (old: raw 327850, padded 2^19=524288) → scripts/fp127_aurora_runner.sh <wire>. At fixed |U|=4096 the R1CS grows ~order-of-magnitude → Aurora prove likely OOMs (was already heavy at 2^19). Build chain couples to default ./target (iCloud) + a C++ libiop build → its own env handling. DEFERRED: foundation-neutral (P0), and the zkVM ρ*-fixed number (88.95 min) + the direction (static faster) already stand. If pursued: re-emit off-iCloud, expect OOM = the finding.
- Papers still NOT in ~/Downloads (W4 lit-numbers pending).
- This iteration: W4 VEIL-wiring assessment (the PQ-ZK pursuit) — agent launched.

### 2026-06-24 loop (W4) — VEIL-wiring assessment: NO-GO quick PoC + SKEPTIC CORRECTION
- Agent verdict: NO-GO for a ZK masked PoC of a single PLUM sub-protocol via VEIL's shipped API. Panic zk/inner/prover.rs:586-596 dedups eval-claims per PCS commitment ("multiple eval claims on same commitment breaks ZK"); PLUM-verify's sumcheck+Basefold/FRI opens commitments at multiple points → fires. Non-ZK override ~2 days, proves nothing about PQ-ZK.
- ⚠ SKEPTIC CORRECTION (do NOT carry agent's "fundamental ZK property" claim): masked FRI/Basefold (Haböck-Kindi, standard PQ-ZK) opens commitments at MULTIPLE points and IS ZK via the mask polynomial — masking preserves ZK, not one-opening-per-commitment. VEIL's guard = specific-API/stacked-PCS design constraint, NOT fundamental. Agent admits it could not read the actual Basefold composition (inferred). Prior research (a5001) = crypto settled-favorable (masking→IT-HVZK). Consistent with engineering-block, not fundamental-block.
- NET (honest): PQ-ZK of PLUM-verify is ENGINEERING-blocked by 7/20 — no quick VEIL-API PoC; sound path (deeper VEIL integration OR direct masked-FRI) is multi-week/post-deadline; NOT fundamentally impossible. Deliverable = obstruction-characterization + masked-construction spec + named blocker. W4 RESOLVED (honest-block).
- Remaining: W2 AI-tell sweep, then loop reports + stops.

### 2026-06-24 loop (W2) — AI-tell + consistency sweep DONE; LOOP COMPLETE
- Em-dashes (---): NONE across manuscript. RQ/EQ scaffolding: NONE ("research question"/"falsified prediction" matches are normal prose/headings). No-AI-tells discipline holding.
- Fixed: premise T2 → premise~(T2) at 03-preliminaries.tex:740 + 055-security.tex:289 (earlier: 055:238 + the degree-5 factual error).
- FLAGGED (Operator taste-calls, NOT changed): #5 antithesis (:25-26,:362,:391 — precise technical contrasts not flourishes); "Al~Kindi" rendering (:364 — uncertain canonical form).
- LOOP STOPPED. Final state: W1✓ remeasure (88.95min/14.7GB/no-OOM); W2✓ sweep; W3✓ significance evidence; W4✓ engineering-blocked verdict (not fundamental). Open: Aurora-arm ratio (mixed params), (a)/(b) PQ-ZK deliverable decision, commit branch + build-env fixes, papers to download.

### 2026-06-24 — 5 SoT agents + architecture map (VERIFIED findings)
- 5 source-of-truth agents in .claude/agents/ (signatures, ao-hash-security, zkvm-precompile-measurement, security-anonymity, proving-architecture); registered via /reload-plugins (21 agents total).
- Architecture map → docs/proving_architecture_map_20260624.md. Directly VERIFIED load-bearing findings:
  1. Dedicated Griffin-Fp192 precompile is SP1-ONLY (precompiles/griffin_fp192/air.rs); RISC0 has none (guest software → sys_bigint). REFRAME: precompile contribution is SP1-specific. (Security section already notes RISC0 arm ran without the chip — verify contribution/eval prose matches.)
  2. VEIL (slop-veil) DEAD CODE — workspace member only, no crate depends (Cargo.toml:202).
  3. STIR gadgets = src/primitives/r1cs/*_fp192_gadget.rs (not loquat/r1cs_circuit.rs, the Fp127 template); full PLUM-80 circuit projected not built. Fixed proving-architecture-sot pointer.
- LOOP TODO: reconcile thesis prose so precompile claims are SP1-scoped + VEIL framed as not-a-live-path.

### 2026-06-24 reconciliation loop — iter 1: architecture-reconcile (proving-architecture-sot)
- VEIL: NO fix — never mentioned in the manuscript; PQ-ZK told via the wrap obstruction only. Confirmed conservative.
- Griffin-SP1-only: BODY already clean (05-system, eval honest-reading + Threats-to-Validity + CreGen-anomaly, 055-security all scope Griffin→SP1 / sys_bigint→RISC0). Confirmed-already-right; do not touch.
- APPLIED (scope-tags, framing untouched): 01-intro.tex:73 Contributions item — Griffin precompile now "(a bespoke AIR on SP1; on RISC~Zero the same arithmetic is carried by sys_bigint)" [highest priority — Contributions read in isolation]; 06-evaluation.tex:893 — 56.4× now tagged "on SP1". Kazuesako lens: pass (precision-add).
- NEXT: substrate-ratio caveat [zkvm-sot] → inversion-envelope → Loquat-L/B caveat [signatures-sot] → PQ-ZK-consistency → Slidev-alignment → STIR-proximity INVESTIGATION [signatures-sot+arch-sot].

### 2026-06-24 reconciliation loop — STORY-SUFFICIENCY (security-anonymity-sot)
- VERDICT: SUFFICIENT to write the story now; all gaps sharpening-only, none blocking.
- SOLID: eIDAS-2.0 gap+dates; Thaler-bounded harvest-now; everlasting-vs-computational; AQ7/Longfellow referent; dual-obstruction headline. All primary or honestly-scoped.
- DEFENCE boundary claims (verified, hold the line): Thaler → "correct for statistically-hiding; mine proves c=H(w‖r) in-circuit → computationally-hiding root → harvest-now applies to my class; the 'just don't prove it in-circuit' rebuttal lands inside my named obstruction" (d7-sh-commitment.md:115-157). Everlasting → "I deliver computational PQ-anon in QROM, not everlasting; everlasting needs std-model SH trace commitment = named obstruction" (d7:132-143, pq-vs-it:48-71).
- DISCIPLINE (G5): every PQ-authenticity sentence conditional on open QROM lift; every anonymity sentence conditional on (T4) + computational-QROM-not-everlasting. Manuscript tags it; the SPOKEN defence must too.
- GAPS (his-action, sharpening): download ePrint 2025/1030 + Moran-Naor (confirm before quoting); the anon-cred→everlasting TRANSFER is the author's framing. Verify-before-slide-quoting: TS4/TS13 verbatim vs primary EUDI PDF; GRI 34→49%.
- Pegasus 2025/1841: VERIFIED at bib level ("(Q)ROM Security" + "Power Residue PRFs" + Sigma-protocol) — matches 055-security.tex:69-73.

### 2026-06-24 reconciliation loop — STIR-proximity investigation (signatures-sot, read-only)
- VERDICT: BENIGN. The proximity/final low-degree test is PRESENT and standard, verified line-for-line vs PLUM Alg 6 line 18 (p.122): native verify.rs:657-782 (FinalPolynomialMismatch); in-circuit ood_finalpoly_fp192_gadget.rs:126-149 + plum_verify_fp192_gadget.rs:323-329 (enforced R1CS eq, tamper-tested at gate scale). All four checks (fold/OOD/rate-correction/final-LDT) wired.
- FALSE POSITIVE source: STALE doc-comment verify.rs:38-69 ("Deferred… EUF-KO does NOT close") contradicted by the code below it. RECOMMEND correcting the comment (Operator's call — touches EUF-KO framing; not edited).
- Residuals (Operator judgment, NOT the alleged gap): (a) fold-consistency rejection masked by earlier Merkle-path check (sound, untested-in-isolation); (b) in-circuit final-poly gadget takes rate-corrected fiber values as inputs + byte-packing modeling boundary = gadget-soundness (proof-checker / Assumption-1 territory), INFERRED-needs-deeper-read; (c) STIR 2024/390 unreached (403) — "canonical batching" INFERRED not verified vs STIR lemmas.
- Naming applier a4bd5767 still in flight; manuscript-touching items (contribution consistency, caveats) wait on it.

### 2026-06-24 reconciliation loop — naming conversion APPLIED + GREEN BUILD; citations verified vs primary
- NAMING: (T1)-(T4) → Assumption 6.1 (asm:air, Griffin-AIR soundness) + 6.2 (asm:szk, PLUM transcript sim); (T1) lookup + (T3) black-box folded to prose hypotheses; B-1..B-10 → B1..B10. 9 files; \newtheorem{assumption} added (main.tex:31). BUILD GREEN: platex+dvipdfmx (NOT xelatex — pxchfon/japanese-otf + dvipdfmx driver), 96-page PDF, no undefined refs. Deliverable B untouched. (applier a4bd5767)
- CITATIONS verified vs primary PDFs (2026-06-24):
  - Griffin (2024/347 FreeLunch 7/10 p.1+Tbl3; 2025/259 Resultant 8/10 p.1+Tbl6; "most variants fail"=Resultant's phrase): broken instances α=3, t=12, 55-bit prime. ⚠ NEW FLAG: Griffin spec 2022/403 Tbl2 p.20 gives R=15 for (d=3,t=4,κ=128); thesis uses 14 "by the Griffin heuristic" (055-security:293) — heuristic gives 15, field 256→199 pushes R up. 14 is likely PLUM's choice — fix attribution / correct / note. Operator's call.
  - Everlasting anchor 2025/1030 "Everlasting Anonymous Rate-Limited Tokens" (ASIACRYPT 2025): everlasting via statistically-hiding PAIRING-based commitment, NON-PQ soundness, rate-limit-bounded → REINFORCES dual obstruction; do NOT cite as "PQ everlasting".
  - QROM lift: 2025/2166 (Chiesa-Di-Hu-Zheng) NAMES STIR, adaptive PQ soundness — primary cite for Deliverable 1; CMS 2019/834 for ZK-in-QROM (insufficient alone). Pegasus 2025/1841 (PRF QROM) confirmed. None closes PLUM's own FS lift → (T4)/asm-area stays open.
  - Masked-FRI 2024/1037 (Haböck-Kindi) Thm 4 = perfect HVZK, soundness-neutral (HVZK/basefield, not PLUM-192-instantiated). VEIL 2026/683 = MULTILINEAR wrapper (NOT masked-FRI — corrected agent facts). Hobbit 2025/1214 = 1.1hr/4.2GB for 2^28 circuit (W4 RAM gap). logup 2022/1530 Lemma 5, char p>N hypothesis. Blendy 2025/1473 name-mismatch (paper="Time-Space Trade-Offs for Sumcheck", no venue).
  - 4 verified cites NOT yet in ref.bib (2025/1030, 2025/2166, 2019/834, + masking) — candidate adds, insertion 02-related.tex:16-27.

### 2026-06-24 — bib adds + quick fixes (build green) + proposal-delta
- ref.bib: added cryptoeprint:2025/1030, 2025/2166, 2019/834, 2024/1037 (metadata off PDFs; not \cited — author places). NOTE 2024/1037 authors = Haböck & Al Kindi → the "Al-Kindi rendering" standing item is this co-author's name typesetting, NOT the historical al-Kindi (earlier explanation corrected).
- verify.rs:21-69 stale STIR doc-comment FIXED (removed false "deferred/EUF-KO does NOT close"; now: test implemented + tamper-tested; open item = Griffin-AIR constraint-soundness assumption). Comment-only.
- Blendy: NO-OP (thesis never cited 2025/1473). Minor unacted: verify.rs:747 prob example annotated PLUM-128 vs measurements PLUM-80.
- Build: platex+dvipdfmx, 96pp, zero bibtex warnings.
- PROPOSAL-DELTA (修論計画書 2025-08 vs thesis 2026-06): half the nouns pivoted (Loquat→PLUM, Jolt→SP1, zkLLVM/Circom→Aurora/Fractal), verdict flipped (which-wins → "not yet"), flexibility lever measured to carry no walltime win. BUT Sako's image already moved at 2026-05-25 (PLUM/measure-substrate endorsed) → defense gap narrower than doc-delta. LIVE gap = R1 (flexibility lever she signed onto is partly nullified). STRONGEST bridge = R4 (dual obstruction IS the true-ZK+speed concern she wrote into the proposal herself). Framing is Operator's.

### 2026-06-24 — Griffin round-count attribution FIXED (signatures-sot verdict: REFUTED)
- PLUM §4.2 p.124 + Loquat §6.2 p.34 / App C.1: NEITHER prints a Griffin round count (only state width 4/3, capacity 2, per-perm R1CS 110/88; "instantiated as in Loquat"). So 14 is NOT from the literature.
- 14 = implementation's own ⌈1.2×11⌉ (griffin_p192.rs:458-491,566-588), floor 11 for (d=3,t=4,λ=128,199-bit). Thesis mis-attributed it to "the original Griffin Gröbner heuristic".
- FIXED 055-security.tex:292-295: re-attributed to "our own instantiation, derived by the Griffin methodology at our params as ⌈1.2×11⌉"; neither PLUM nor Loquat prints it. Prose-only; methodology + 20%-margin + FGLM-2^64 kept; honest "not yet frontier-validated" already at :306-309.
- (Griffin spec 2022/403 Tbl2 R=15 for (d=3,t=4,κ=128,256-bit) verified earlier by ao-hash-sot; 14 is the 199-bit re-derivation, not the table value — additional reason the bare "fixed by the heuristic" was misleading.)

### 2026-06-24 — contribution-framing consistency (security-anonymity-sot) + LOOP STOP
- CONFIRMED no drift across 01-intro/06-eval/07-discussion/08-conclusion + abstract. Invariant 1 (PQ-ZK=engineering-blocked-not-fundamental) and Invariant 2 (precompile=instrument+falsified-prediction, not "the win") both hold; consistent with 055-security:439 canonical scope.
- OPTIONAL hardening (NOT applied, Operator's call): 08-conclusion:27 "no amount of additional memory...removes either" reads terminally standalone; an optional cross-ref to the future-work para immunizes it.
- LOOP STOPPED (stop condition met: naming green-build + contribution consistency clean + all his-calls surfaced). No further auto-scheduling.

### 2026-06-24 — Deliverable-B citation verification vs 5 primary PDFs (security-anonymity-sot)
- Everlasting Remark/Proposition is DRAFT-only (NOT in committed 055-security) — fixes apply before insertion. Verified-before-shipping caught:
  - HNORV MIS-CITED for "no-both-statistical" (it only remarks it, no proof) → re-cite no-both to folklore (Goldreich FoC v1); use HNORV for its Thm 1.1 (SH-from-OWF exists).
  - BDLOP param "m>3n log q" REFUTED (plain-SIS form; BDLOP is ring R_q knapsack) → real condition Lemma 4 p.8 (Module-LWE/LHL); hiding=Module-SIS, binding=Module-LWE, can't-both-be-statistical = the no-both fact.
  - Wee bound is Ω(n/log n) NOT ω — fix typo.
  - CGH ✓ INHERITED — soften to "methodology warns", not "proves this commitment fails".
  - HHRS ✓ INHERITED — scope to fully-black-box (structured-assumption SH commitments escape it).
- Clean obstruction structure: HNORV(SH-from-OWF exists) ∧ HHRS+Wee(Ω(n/log n)-round → non-interactive needs structure) ∧ BDLOP(PQ-structured candidate, β-bound, opening interactive) ∧ folklore no-both.
- bib metadata captured for all 5. B foundation now sound; pending Operator "insert B" + the Bn→names appendix rewrite (awaiting go).

### 2026-06-25 — Deliverable B INSERTED + green build (Operator: "proceed with B", style=his voice, no footnotes/overclaims)
- Added 4 bib entries (cgh2004rom, hhrs2007, wee2007tcc, bdlop2018) — HNORV NOT added (no-both fact is folklore, stated without citing it; HNORV mis-cite avoided).
- 055-security.tex §zk-gap (after :441): QROM-lift paragraph (cryptoeprint:2019/834 CMS + 2025/2166 STIR-class; conditional on asm:szk + PLUM FS, open); Remark rem:everlasting (computational-not-everlasting; c=H(w||r) in-circuit; CGH instantiation warning; HHRS+Wee Ω(n/log n) scoped to black-box-from-OWP; no-both folklore); Proposition prop:everlasting + proof sketch (conditional everlasting via non-interactive PQ SH trace commitment); BDLOP candidate (interactive opening → gap open).
- 5 citation fixes applied: HNORV→folklore, BDLOP no "m>3n log q", Wee Ω-not-ω, CGH "warns", HHRS black-box-scope. Style: plain declarative, no footnotes, no em-dashes, conditional, in Operator's voice.
- BUILD: latexmk platex+dvipdfmx, exit 0, 98pp, no undefined refs/cites, 4 new keys in main.bbl.
- PLUM vs Loquat (Operator Q): PLUM = focus/headline (holder's scheme); Loquat = reference baseline only (predecessor + Aurora substrate, since PLUM not runnable in Fp127 harness). Loquat NOT a co-spine.
- C2 now FORMALIZED. Remaining: quick caveats (substrate-ratio/Loquat-L-B/inversion-envelope), Bn→names (pending Operator approach-confirm), cost-model-postdicts-inversion (P1), contribution prose (Operator), #5 antithesis, commit ρ*-branch.

### 2026-06-25 — caveats + Bn→names applied + green build
- 3 caveats (06-evaluation): substrate-ratio direction-only (|U|=4096 vs 256); Loquat L/B not security-calibrated (rate paper-faithful post-ρ*); inversion 1.10–2.45× = envelope, sign robust. No numbers/results changed.
- Bn→names: 35 B-codes removed, zero B[0-9] remaining in 05-system/055-security/appendices. Group names + per-family descriptive names; per-row vs cross-row row-scheduling distinction preserved; 2 lemma titles renamed. No logic/ref/label changes.
- BUILD: latexmk platex+dvipdfmx exit 0 ×2, no undefined refs/cites, 98pp.
- Trivial flag (unfixed): appendices.tex:503 redundant "round count" — one-word tidy available.
- Manuscript state: Deliverable B in; naming = Assumptions + named families (no codes); citations primary-verified; honest caveats in; green build. Remaining = contribution prose (Operator) + §4 cost-model-postdicts-inversion check (P1).

### 2026-06-25 — /kazuesako-paper-review §6 Security + appendix (deadline mode)
- HEADLINE: reductions ALREADY game-based (appendix app:preservation has G0/G1/G2 anonymity, forger B + extractor E unforgeability, def-with-error-terms, eq:adv-unf/eq:adv-anon). External "not game-based" critique does NOT hold — it read only the body. Chapter PASSES the model.
- 🟡 should-fix: (1) unlinkability reduction asserted but unwritten → APPLIED (appendices.tex, full short proof, ε_ZK+ε_sZK); (2) anonymity-bound vacuity on deployment → already stated at :200, no edit (avoid repetition); (3) black-box-transfer hypothesis :178 "argued from structure" → SURFACE: needs pointer into PLUM's reduction (signatures-sot vs PLUM paper); (4) knowledge-soundness generic-vs-concrete cite → APPLIED (":252 now 'applied to the two systems' concrete arguments'").
- 🟢 polish: (5) QROM caveat twice (threat-model unforgeability vs B anonymity — different properties, check not redundant); (6) ε_EUF provenance PLUM-Thm1-vs-Loquat — make consistent.
- BUILD: exit 0, 98pp, no undefined.
- VERDICT: passes the model; before Sako = write unlinkability (done) + ground black-box-transfer (#3, Operator). Rest polish. NOT a reductions-rewrite.
- NEXT (loop): kazuesako on intro+abstract (framing gates 1–4) — surface for Operator, do not write framing.

### 2026-06-25 — black-box-transfer hypothesis VERIFIED vs PLUM (signatures-sot) + upgraded
- VERDICT: CONFIRMED. PLUM §3.2 p.118 verbatim: "modifications only affect the underlying building blocks, which are treated as black boxes, the corresponding security proofs carry over from Loquat directly." Reduction (PLUM Thm 1 proof p.120-121) programs the hash as a random oracle ("programs the output of the random oracle H1...") + computes field ops at value level; never opens Griffin internals. Benign RO-programming case, not internals-opening.
- Caveats: classical-ROM only (thesis already scopes); Loquat App B.3 unread but PLUM reproduces inline (low risk); distinct from asm:air (precompile computes reference-Griffin, still open).
- APPLIED 055-security.tex: "argued from the structure" → "established by PLUM's own analysis (programs hash as RO, value-level field ops; PLUM §3.2 + carries over from Loquat)" (×2 sites :108 + :117); moved black-box-transfer OUT of the not-yet-closed list → now THREE open inputs (asm:air, asm:szk, quantum lift) not four. Build exit 0, 98pp, no undefined.
- Security chapter Sako should-fixes now CLEARED: unlinkability written (appendix), black-box-transfer cited, knowledge-soundness concrete-arguments clause. Open premises reduced to the irreducible 3.

### 2026-06-25 — /kazuesako-paper-review intro + abstract (framing gates, deadline mode)
- Intro PASSES gates 1/3/4: title now "Locating the Deployability Wall" (agility overclaim GONE); §1.1 names decider (university consortium) + external need; §1.5 dual obstruction = central finding; precompile = instrument; scope + open premises explicit.
- 🔴 BLOCKING: abstract (main.tex:115) vs body (01-intro:69) CONTRADICTION. Abstract: "Both BDEC relations proved on SP1, CreGen 27–31 min, presentation 40–44 min." Body: CreGen prove terminated in an ANOMALY (didn't complete), CreGen on RISC Zero (not SP1), no clean BDEC-relation prove times in benchmark record. Contradiction on completion + substrate + numbers. Needs Operator measurement truth (offer zkvm-sot to verify vs logs). DO NOT guess.
- 🟡 should-fix (framing, Operator): (1) contribution named two ways — §1.1:9 "comparison is the contribution" vs §1.5:66 "dual obstruction is the central finding" → align (obstruction=contribution, comparison=method); this is the source of the recurring "what's my contribution" confusion. (2) 32.5 vs 14.89 min PLUM-verify reconcile + state config.
- 🟢 polish: §1.3 title "Cryptographic Rigidity" — the agility-family term the professor flagged; rename optional.
- No blind edits (blocker needs Operator truth; rest is framing). NEXT: 06-evaluation (verify caveats/numbers), then 02-related, 08-conclusion.

### 2026-06-25 — 🔴 BLOCKER RESOLVED (abstract-vs-intro BDEC prove numbers)
- Ground truth (06-evaluation.tex:443-444,453-454,555-556): CreGen SP1 prove COMPLETES 26.98+31.11 min (n=2); ShowCre SP1 40.15+44.24 (k=1), 58.14 (k=2); CreGen RISC Zero = anomaly (≥15.6h, internal-verifier rejection).
- VERDICT: abstract (main.tex:115) was CORRECT — numbers measured, on SP1. The INTRO §1.5(1) was INCOMPLETE — mentioned only RISC0 CreGen anomaly + SP1 standalone-verify, omitting the SP1 BDEC-relation prove completions. NOT an abstract overclaim (my initial flag was wrong-direction; checking logs prevented deleting true numbers).
- APPLIED 01-intro.tex:69: added "on RISC Zero CreGen anomaly … whereas on SP1 both BDEC relations complete a succinct non-ZK prove (CreGen 26.98/31.11, ShowCre 40.15/44.24 k=1, 58.14 k=2)". Abstract/intro/eval now consistent. Build exit 0, 98pp.
- Sharpens dual obstruction: base proofs COMPLETE on SP1; the wall is the ZK wrap specifically.
- Remaining intro should-fixes (Operator framing): contribution-naming align (§1.1:9 vs §1.5:66); 32.5-vs-14.89 choice; §1.3 "Cryptographic Rigidity" title.

### 2026-06-25 — P1 cost-model verification (zkvm-sot) + P3 demoted
- P1 VERDICT: STRONG. §4 cost model HAS the prover-side own-AIR term A_P (04-theoretical:52), wall-clock Eq trace-area-model (:56), pay-iff Eq precompile-pays (:64). Earlier "predicts opposite / no AIR term" flag (thesis_coherence_audit_20260606) is STALE — it predated the A_P term. Model postdicts the Griffin-vs-SHA-3 slower sign. P1→P2 weld holds.
- HONEST NUANCE: sign-postdiction vs the SHA-3 control is near-trivial (control fires no Griffin chip → Griffin arm strictly dominated, more cycles + chip area). Model's genuine content is the OTHER operating point (feasibility recovery, precompile-vs-emulation). Strong framing = "one inequality, two operating points, opposite outcomes" — ALREADY in intro §1.5(3) + 04-theoretical:68 + 06-eval:227. Do NOT pitch as "model predicts the slowdown" (trivial). Magnitude 1.10-2.45× honestly NOT postdicted (build-sensitive envelope).
- Residual (minor, already provisoed): "both terms larger" rests on ā_core common to both arms — stated as proviso (§4:68), not measured per-arm. No edit needed.
- P3 DEMOTED: intro §1.5 item 4 retitled "A secondary dimension: update churn and a deployment decision framework" (was co-equal "measured dimension + practitioner framework"). Build exit 0, 98pp.
- Spine solid: P4 → P1(verified) → P2 → P5; P3 off-spine.

### 2026-06-25 — /kazuesako sweep: 02-related + 08-conclusion (deadline mode) + LOOP STOP
- 02-related: PASSES. Novelty statement (line 56) exemplary — disclaims "first PQ sig in zkVM" (cites s2morrow/HAPPIER/Dilithium-in-SP1), narrows to "first algebraic-hash PQ anon-cred in a zkVM"; honest vs CAPSS; already calls churn "the secondary axis" (consistent w/ P3 demotion). 🟢 only: "cryptographic rigidity" term (agility-family, professor flagged) — surface.
- 08-conclusion: APPLIED consistency fix (line 11) — added SP1 succinct BDEC completions (CreGen 26.98/31.11, ShowCre 40.15/44.24/58.14), scoped anomaly to RISC Zero; now consistent w/ intro+abstract+eval. 🟢: "Future-proof" (line 27 Closing) agility-family term — surface.
- Build exit 0, 98pp.
- LOOP STOP: load-bearing sweep complete (security passes; blocker resolved; P1 verified; intro/conclusion consistent; novelty strong). Remaining = framing (Operator) + low-yield setup (03/05/07). No further auto-scheduling.
- SURFACED for Operator (framing): contribution-naming align (obstruction); 32.5-vs-14.89 number; agility-family terms (§1.3 title, 02-related x2, conclusion Closing); §7 framework read-as-secondary (consistent w/ P3 demote).

## Audit 15 — 2026-06-28, WRAP-OBSTRUCTION MECHANISM (new same-machine data supersedes the memory framing)
Mode: formative. Trigger: 7-experiment zkVM session (docs/measurements/zkwrap_*_2026062*/RESULT.md) established the ZK-wrap is NOT memory-bound.
1. 🔴 NEW (cross-chapter: 01-intro:71, 06-eval:241/245/523, 055-security:410) — the wrap obstruction is stated as MEMORY exhaustion ("exhausts memory at ≈20 GB", "killed under memory pressure, peak RSS 19.98 GB"). Newer same-machine data: the 19.98 GB kill is a jetsam artifact of SP1's DEFAULT 8-worker prover concurrency; throttling to SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2 runs the SAME workload at ≤13 GiB and gets PAST the memory point, dying instead on a STRUCTURAL recursion-shape capacity wall whose sound fix is a ~25h, 185,862-setup vk-allowlist regeneration (compress_shape.json → vk_map.bin coupling). Memory is NOT the binding constraint. Settings-skepticism on a NEGATIVE datum: ~20 GB is the default-concurrency setting, removable. FIX: reframe the wrap leg of the dual obstruction from "exhausts memory" to "blocked by a one-time cluster-scale toolchain regeneration that more memory does not remove" — which makes the intro's existing "partly a toolchain fact that more memory does not remove" clause (01-intro:71) literally true rather than half-hedged. Dual-obstruction CONCLUSION (receipt not-ZK + wrap not-produced → anonymity not delivered) SURVIVES unchanged; only the mechanism of the wrap leg updates.
2. 🟡 NEW — asymmetric settings-disclosure: Cell 2 CORE OOM-at-default is disclosed (06-eval:75 "at default settings OOM-killed at 3 min"), but the WRAP kill (06-eval:523, 19.98 GB) is NOT disclosed as default-concurrency-dependent. Apply the same lens at the point of claim.
3. 🟡 NEW — 01-intro:27 "the full credential relation's succinct proof did not complete, in an anomaly examined in §5" reads against the now-integrated SP1 BDEC completions (intro:69, 06-eval:447, conclusion:11). Verify line 27 is scoped to the RISC Zero anomaly, not read as a blanket non-completion. (Possible residual of the pre-6/11 framing on a line the 6/25 fix didn't touch.)
4. 🟢 NEW — figs/tikz/memory_frontier.tex is orphaned (defined, never \input/\ref). It is the natural home for the corrected "memory is not the wall; the wall is structural" datum — wire it or cut it.
5. 🟢 NEW — "exhausts memory / killed at ≈20 GB" restated in ~6 places; after the reframe, sweep so the caveat lives once in the resource-frontier subsection (count: 6 — 01-intro:27, 01-intro:71, 06-eval:241, 06-eval:245, 06-eval:523, 055-security:410).
Verdict: was at "passes the model, remaining = framing" (6/25). This session reopens ONE blocking item on §5.5/§6 — the wrap mechanism — because the underlying fact changed (memory → structural). Fix finding 1 and it returns to the 6/25 pass state. NOT a security-logic failure; a factual-mechanism update that strengthens the obstruction.
Caveat: the ~25h figure is EXTRAPOLATED (2 slices @ ~0.5s/setup × 185,862), not an observed end-to-end run; the gnark wrap-stage RAM remains genuinely unmeasured. State both as such if cited.
LOOP STOP: review delivered; one-shot. No further auto-scheduling (pending 02:55 wakeup will not re-arm).

### Resolution — 2026-06-29, §4 cost-model Option B APPLIED + re-audit residuals fixed (build EXIT 0, 101pp)
§4 cost-model gap (Audit-16 SIXTH / theoretical 🔴) RESOLVED via Option B (scope to core prove, NOT add ungrounded recursion term): 04-theoretical model intro "Prover wall-clock"→"per-shard core-proving component"; A_P-omit sentence + "both terms price the per-shard core prove; recursive-compression/wrap is a separate regime, measured in §6, not in this model"; Prop precompile-pays "lowers prover wall-clock"→"lowers the core-proving wall-clock"; :142 de-claimed end-to-end + added qualitative D3 pointer (Griffin chips enlarge the recursion verifier → the provisioning wall, §6). §4↔§6 inconsistency closed.
RE-AUDIT (both new auditors, post-edit) caught 3 REAL residuals earlier passes missed, all FIXED: (1) 06-eval:1053 "wrap memory exhaustion" in §6 limitations list (Audit-16 sweep didn't cover it) → "recursion-shape provisioning wall"; (2) 06-eval:542 the ~51h cite pointed to zkwrap_vkmap_slope dir which has NO RESULT.md (only slope.out = rate) → now cites slope (rate) + failure_map (extrapolation); load-bearing because the §055 trim defers here; (3) 06-eval:529 "≈17.8 GB sampler" cited to worker_concurrency whose default-conc sampler is n/a → now cites bench_suite_20260529_overnight (sampler). Consistency otherwise CLEAN (25 wall-occurrences, 1 name, 0 variants; tonight's edits introduced no drift).
SURFACED not fixed: 06-eval:1007 "memory-exhaustion walls" plural (low-conf, defensible = Cell-1+Fractal); "83% of 24 GB" is 83% of NOMINAL (77.5% of physical 24 GiB) — caveat, not error. STILL OPEN (Operator): standalone abstract abst_Takumi2025 stale+untouched; 14.89min/6h19m lack RESULT.md; framing half (contribution re-rank, prong asymmetry, PQ-ZK overclaim, two-titles); λ=128 & gnark-RAM unmeasured (disclosed); asm:air open.

### Resolution pass — 2026-06-28 (Operator: "honest" now; "definite" deferred until the regenerated toolchain / gnark stage is measured)
APPLIED the honest (non-overclaiming) reframe, execution-class chapters only; build exit 0, 100pp, no undefined refs:
- 055-security:410 — obstruction 1 relabelled "resources"→"toolchain provisioning, not memory"; default-concurrency kill + throttled ≤~17 GB + structural recursive-compression wall + one-time regen (~a day) + "regenerated-toolchain/24 GB feasibility not measured here" + "not generated on the stack as shipped" (dropped "infeasible").
- 06-eval:520 (ssec:resource-frontier) — full honest mechanism lives HERE (Sako finding 5, caveat-once): "Two failures bound the frontier"; item 1 rewritten to structural; ML-DSA item 2 unchanged.
- 06-eval:245 — short pointer ("does not complete as the toolchain ships—not for want of memory…").
- 04-theoretical:142 — "resource frontier"→"frontier… (former on memory and time, latter on static recursion provisioning)".
NOT touched (deliberate, framing = Operator): 01-intro:27, 01-intro:71 (Draft 2 handed over). 05-system:95 left (neutral pointer, no memory claim).
RESIDUAL for Operator: (a) 01-intro:71 still says "partly a resource limit and partly a toolchain fact" — now CONTRADICTS the body until aligned via Draft 2; (b) 🟢 §6 subsection title "The genuine resource frontier" — item 1 no longer a resource failure, may want retitle (label ssec:resource-frontier must stay for refs); (c) DEFINITE-claim trigger: escalate 410/520 from "not generated as shipped" to a settled-infeasibility claim ONLY after measuring the regenerated vk_map/gnark stage (per Operator).

## Audit 16 — 2026-06-28, WHOLE-THESIS RECALIBRATION (7-section parallel Sako fan-out + synthesis)
Mode: formative. Trigger: Operator "spawn agents for each section and recalibrate as a whole as Sako." 7 parallel reviewers (intro+abstract, theoretical, system, security, evaluation, discussion+conclusion, related+prelim) against the 6 session deltas + her full method.
DOMINANT FINDING (every reviewer, consensus): the memory→structural reframe (D1) was applied to only 2 PARAGRAPHS (055:410, 06-eval:526) and is CONTRADICTED in ~17 places — one object, two names, thesis-wide. Sako would reset the meeting to this (gate-1/consistency). Narrative arc BREAKS at the central finding (why the wrap fails), but is RECOVERABLE (structure sound).
Stale "wrap = memory/resource" occurrences: 01-intro:66,71; main.tex:115; 08-conclusion:7; 07-discussion:31-34,37-38; 06-eval:567(table),581-582(caption),685-687; 055:205,241,357,373(fig),384(caption),434,444; appendices:66. (08-conclusion:29 + 02-related:19/31 already aligned.)
SECOND consensus: D3 precompile paradox (Griffin SOLE cause of recursion overflow, +276,768 ExtAlu/+34.8%, byte-for-byte) is in NO prose — flagged by §4 (no model term — 🔴, model prices core layer only, incomplete in the dimension D3 exposes), §5 (chapter promises "attributed", doesn't deliver — its home), §6 (measured, unreported — its data home), intro (undersells contribution 3; D3 unifies contributions 2+3), discussion ("What Generalises" is its home).
THIRD: dual-obstruction ASYMMETRY (055 🔴-2) — prong1 now surmountable-but-untested (~51h, 24GB-sufficiency unmeasured, caused by own precompile); prong2 (pairing≠PQ) fundamental. Thesis mis-frames them co-equal.
FOURTH: BDEC consistency (D6) — §5:14-15/97-98 + intro:27 imply BDEC only ran RISC0/no proof; contradicts SP1 succinct completions in conclusion:11/eval table.
FIFTH: two-documents/two-titles — standalone abstract (abst_Takumi2025) titled around agility-tax (demoted), older, different story than thesis.
SIXTH (deepest): §4 cost-model prices core layer only; D3 proves a recursion-layer cost the model has no symbol for → add recursion term OR explicitly scope model to core prove.
PQ-ZK note: VEIL (masked-FRI) DOES ship in the SP1 fork (unwired) per 08:25 — so PQ-ZK path is "wire+test", not "build", BUT D3's recursion-tax propagates into VEIL too; conclusion:25 "wire one in + check memory" overclaims it as engineering errand.
PASSES (specific praise): motivation (intro:9 university-consortium decision-maker), novelty (02-related:56), FMT def+lower-bound (§4), Theorem 5.1 complete contract, anonymity-bound conditionality (computational-not-everlasting, classical-not-quantum, §055).
ACTION: EXECUTION half delegated to engineer-agent (memory→structural sweep in 055/06-eval/05/appendices ONLY; add measured D3 to §6 data-home + §5 forward-ref; BDEC consistency in §5; gate-5 cites; tab:bdec k=2 n=1; jetsam wording). FRAMING half SURFACED to Operator: intro/abstract/conclusion/discussion memory sweep; dual-obstruction asymmetry; contribution re-rank (unify C2+C3 via D3); §4 model decision; two-titles; PQ-ZK honesty (VEIL+tax).

### Resolution pass — 2026-06-28, EXECUTION half APPLIED (engineer-agent, 21 edits, 4 files) + build verified
APPLIED in 055-security/06-evaluation/05-system/appendices ONLY (independently rebuilt: latexmk EXIT 0, 101pp, zero undefined refs):
- Memory→structural sweep: 055:205,241,357,373(fig),384(caption),434,444; 06-eval:567(table row),581-582(caption),685-687; appendices:66 — wrap failure now reads "structural recursion-shape provisioning", ≈20 GB kept only as default-concurrency symptom.
- D3 paradox ADDED to 06-eval ssec:resource-frontier (new para: Griffin sole cause, +276,768 ExtAlu/+34.8%, byte-for-byte md5 f97a8b2f, cite zkwrap_griffin_shape_attribution_20260628) + 05-system:3 forward-ref sentence. No contribution-ranking language (left to Operator).
- BDEC consistency: 05-system:14,15,98 now carry SP1 succinct completions (CreGen 26.98/31.11 n=2; ShowCre 40.15/44.24 n=2 k=1, 58.14 n=1 k=2; receipt verified, not ZK) distinguished from RISC0 anomaly + open ZK wrap.
- Gate-5 cites added (51h→zkwrap_vkmap_slope_20260628 +≈1s/setup/48-54h; 17GB→zkwrap_default_shard; 19.98GB→zkwrap_worker_concurrency); jetsam wording 055:411; tab:bdec k=2 (n=1).
DEVIATION (flagged): 06-eval:567 dropped leading "no" (Produced? column already reads no). LEFT for Operator: 06-eval:521 subsection title "The genuine resource frontier" (heading=his call, \label kept).
STILL STALE (framing files, agent reported, NOT edited — Operator to sweep): 01-intro:66 ("exhausts memory… measured resource limit"); 08-conclusion:7 ("measured resource bound… additional memory would buy a wrap"); 08-conclusion:11 ("bounded by the same memory frontier"). [01-intro:27, 08-conclusion:19, 07-discussion:83 = genuine Cell-1/Fractal OOMs, correct, NOT swept.]
FRAMING half remains Operator's: those 3 intro/conclusion sweeps + dual-obstruction asymmetry + contribution re-rank + §4 model + two-titles + PQ-ZK honesty.

### Resolution — 2026-06-28, intro/conclusion memory sweep APPLIED (Operator authorized "apply where appropriate")
Applied honest-MINIMAL rewrites (no overclaim either direction; conclusion/verdict preserved): 01-intro:66 (×2), 01-intro:71 (×2), 08-conclusion:7 (×2), 08-conclusion:11 (×1). Build EXIT 0, 101pp. Whole thesis now internally consistent on structural-not-memory. NOT escalated (held for Operator): naming Griffin as cause in intro/conclusion, the prong-1-vs-prong-2 asymmetry, contribution re-rank, §4 model, two-titles, PQ-ZK honesty. Note: Operator voiced a "honesty can destroy the foundation" worry; resolved by showing the verdict ("not yet") + prong-2-fundamental are untouched — only a wrong reason (memory→structural) was corrected; the false "impassable memory wall" was the actual defense liability (collapses under Sako's "did you try other settings?").

## Audit 17 — 2026-06-29, FULL PRE-DEFENSE MOCK (all 10 chapters + standalone abstract), build EXIT 0
Mode: formative→deadline (pre-defense). Thesis build latexmk EXIT 0 (no undefined refs); abstract build EXIT 0.
PART 2 (mechanical) — standalone abstract abst_Takumi2025 sweep APPLIED this session (concurrent process, verified by git diff, not re-edited): title "Quantifying the Performance Tax of Cryptographic Agility…"→thesis title "Locating the Deployability Wall…"; \date{XX/XX/2026}→07/20/2026; \fbox{XX}→"14.89 to 32.5 min (build- and machine-state-sensitive)" matching cover/intro:73/conclusion:9 + honest UNRECONCILED note; "SNARK-friendly custom primitives"→"custom arithmetisation-oriented primitives" (03-theoretical:6) and "SNARK-friendly custom primitive"→"bespoke algebraic-hash primitive" (05-evaluation:23). Sako-rejected term now absent from abstract. Abstract 07-conclusion:4 "personal-device memory budget" RETAINED (correct: that IS Cell-1 OOM, not the wrap).
FRAMING (RECURRING, author's call, surfaced not fixed): contribution re-rank / D3 unify C2+C3; dual-obstruction prong asymmetry (surmountable vs fundamental); PQ-ZK "engineering gap not fundamental" at conclusion:25 + future-work:23; two-titles now reconciled by retitle but abstract STORY (agility-tax-led) still diverges from thesis (wall-led); λ=128-never-measured / n=1 prove / asm:air-open disclosures present but assess whether load-bearing enough at each positive claim. These match Audit-16 SIXTH/THIRD/FIFTH + are the standing deferred-to-Operator set; engagement is real (execution half applied each pass), so NOT a non-engagement escalation.
Verdict: execution-clean and internally consistent post-Audit-16 sweep; remaining gate-level risk is entirely framing (abstract narrative divergence + prong asymmetry). Bring to her once the abstract story leads with the wall, not the tax.

## Audit 18 — 2026-06-29, FULL Sako pre-emption pass (gaiyousho abst_Takumi2025 + thesis), model upgraded with Slack-corpus evidence
Mode: formative. Trigger: Operator ran the full pass after mining Sako's ACTUAL Slack reviews (#announce-seminar, #discuss-mthesis-2024/2025, ~15 students incl. Tsutsumi's 2024 zkVM thesis). Skill SKILL.md updated with verbatim-grounded specifics (gaiyousho discipline, line-level reading, object-vs-related-work, contribution-cell red, term-scrutiny, "says when she doesn't understand").
NEW (genuinely surfaced this pass, actionable, NOT framing):
1. 🔴 abst/sections/03:4: "structural Ω(k²) overhead" is a FACTUAL ERROR — proof-checker today verified the lower bound is Ω(ℓ); ℓ² is the schoolbook UPPER end (Karatsuba does fewer). Fix Ω(k²)→Ω(k) lower / k² schoolbook. Correctness, not the Operator's framing.
2. 🔴 abst/01-introduction: gate-3 motivation-from-outside fails — a SETTING ("personal device"), not a named external decision-maker; the thesis honbun HAS the university-consortium instance, the gaiyousho dropped it. NEW.
3. 🟡 abst/01-introduction:15: "≈91% of the verification cost" unscoped (λ=128 R1CS constraint share, not a measured λ=80 cost) — instance of the standing λ-disclosure flag, now located in the gaiyousho.
4. 🟡 thesis tab:plum-verify: contribution cell (Cell 2, the precompile) not visually emphasized — Sako's verbatim zkVM-thesis strike ("本研究のセルを赤く"). NEW.
5. 🟡 abst/01-introduction:16-18: gate-1 three questions, no single research question.
6-8. 🟢 strip scaffold NOTE comments (01-intro:1-2, 05-eval:15-19, both say "not final"); 03:1 "The"→"the"; "deployability wall" defined late (06-discussion) after the title; 02-preliminaies commented out (OK if terms glossed inline).
RECURRING (standing, deferred-to-Operator framing per Audit 16/17 — engagement real, NOT non-engagement escalation):
R1. 🔴 gaiyousho tells the agility-tax-led / one-prong-wall story: "agility tax" (03,07) vs thesis "field-mismatch tax"; missing the F2 D3 recursion-shape lead; "deployability wall" (06-discussion:11) = ZK/primitive only vs thesis dual obstruction. This = Audit-16 SIXTH / Audit-17 "abstract STORY still diverges (agility-tax-led vs wall-led)". The author's framing call; her first strike but his to resolve.
Verdict: NOT yet. The CORRECTNESS item (Ω(k²)→Ω(k), #1) and gate-3 motivation (#2) should be fixed regardless of framing; the dominant blocker R1 is the standing wall-vs-tax narrative call the Operator owns. Honbun itself holds (this session's work). Gaiyousho framing = his voice; surfaced not fixed.

## Audit 4 — 2026-07-01, 修論2025_Takumi/ @ worktree-thesis-restructure-criterion (criterion-spine restructure, abstract+intro+§4+§6)
Mode: formative.
1. 🔴 REGRESSED main.tex:98/115 + 01-intro — "SNARK-friendly" reintroduced (rejected 2026-05-25; Audit-2 #7), now in the TITLE. Fix: precise descriptor ("low-constraint") or drop ("...Proving Post-Quantum Signature Verification...").
2. 🟡 NEW 01-intro RQ box — two axes bundled (cost + security); Gate 1 single-axis. Name cost criterion as axis; security = second deliverable / deployability = cost ∧ security.
3. 🟡 RECURRING 01-intro fig:two-provers caption — wall-spine emphasis ("locates the deployability wall"/"BDEC baseline"); lead with substrate comparison.
4. 🟡 NEW 01-intro contribution #4 "A secondary dimension" old register vs crisp #1-3.
5. 🟡 NEW 01-intro #3 "first empirical characterisation" — scope/defend "first".
6. 🟢 NEW 04-theoretical — #1/§4 first-names "Griffin" without bridge from "algebraic-hash".
Verdict: not yet — title's rejected term is the gate-stopper; fix it + the two-axis RQ; criterion spine otherwise passes Gates 1-5 (precompile=instrument, BDEC=instance, settings disclosed). Stronger than the wall-spine draft.

## Audit 5 — 2026-07-01, 修論2025_Takumi/ @ 06abc99 (post Audit-4 fix pass + consistency auditor)
Mode: formative (re-review).
RESOLVED: #1 SNARK-friendly (swept title/abstract/RQ/related -> "low-constraint"; 03:148 stance kept; build clean), #4 contribution-#4 register, #5 "first" scoped ("...inside a general-purpose zkVM"), #6 #1 bridges "algebraic-hash (Griffin)"; consistency-auditor 🔴 conclusion-ranking (cost criterion = central reusable result; dual obstruction = central deployability finding), 🟡 assumption-count (security "two of three, QROM upstream"; conclusion folds QROM double-count), 🟡 eval table rows "BDEC CreGen/ShowCre" -> "CreGen/ShowCre".
OPEN (operator framing — not auto-fixed): #2 RQ box bundles two axes (reconcilable via def:deployable = cost ∧ security; needs his wording call); #3 fig:two-provers caption wall-emphasis; + title-term override (defaulted to "low-constraint"); BDEC Applications-section structural decision.
Verdict: passes Gates 2-5 (precompile=instrument, BDEC=instance, settings disclosed, ontology clean). Gate 1 single-axis pends the RQ framing decision (his). Loop paused for operator input — mine-items closed, only framing decisions remain.

## Audit 6 — 2026-07-01, 修論2025_Takumi/ @ 2ece349 (post Gate-1 closures)
Mode: formative (re-review). Gate-1 closed: intro answer-paragraph declares the trace-area cost as the SINGLE comparison axis; the security half (which properties survive) is settled separately as the preservation theorem + the wall, not a second axis; fig:two-provers caption subordinates the wall ("It also locates ... (contribution two)").
ALL FIVE GATES PASS: G1 (goal = when-does-a-precompile-pay, no tool word; single axis declared) · G2 (precompile=instrument, BDEC=instance, criterion/wall=findings) · G3 (named consortium operator) · G4 (goal/approach/deliverable survive) · G5 (inversion 14.25 vs 13.05, 1.09x, n=3, lambda=80 at point of claim; held-out forecast honest about num_bigint apparatus).
Verdict: PASSES THE MODEL on all five gates (first clean pass; Audit 5 had G1 open). Only OPEN item = OPTIONAL BDEC Applications-section structural decision (operator's call, not a gate failure). Loop's productive review-fix work complete; a confirming identical pass would satisfy the two-in-a-row rule.

## Audit 7 — 2026-07-01, precompile #3 "B2" (FP192_POW_RES) — the "a family" first-liner CLAIM @ prf-precompiles fork, post Path-A + proof-checker re-verify (agent a51c1ada)
Mode: formative. Reviewing the CLAIM that the build turns the first-liner "a precompile" -> "a family", NOT thesis prose.
Basis: proof-checker adversarial re-verify — all four constraint-soundness holes CLOSED (chain-binding, off-by-one, byte-injectivity, payload-sufficiency; break-attempts constructed + refuted); NO new false-accept hole; completeness UNVERIFIED (no trace-gen/wiring, never smoke-proven).
Gate verdicts on the "a family" claim:
- G1 (goal/means): PASS — "a family" is the construction/deliverable, not conflated with the goal.
- G2 (ontology): PASS — three genuine instances of ONE precompile interface (i/o-equiv over F_p; isolation via cross-table lookup kind=23; constant baked modulus); B2's soundness argument shares Griffin's shape, not ad-hoc. Requires §5 to state the interface explicitly and show each chip instantiates it.
- G4 (three-sentence): PASS (goal reduce cost / means construct the family / deliverable criterion + family).
- G5 (settings/honesty): PASS **ONLY WITH DISCLOSURE** — the third member is constraint-sound (audited) but NOT smoke-proven (completeness unverified). "a family of three precompiles" is honest iff the 2-proven + 1-sound-not-yet-proven asymmetry is stated AT THE POINT OF CLAIM. Burying "the third never produced a proof" = the "did the third actually run?" G5 failure.
Verdict: the first-liner FLIPS "a precompile" -> "a family" — earned per the Operator's own FORECAST gate (constraint-level soundness, explicitly NOT smoke-prove) AND the Sako-lens, CONDITIONAL on the G5 completeness disclosure. LOOP CONDITION MET. Remaining (optional, operator's call): smoke-prove the third for an unqualified "three that run" claim; add step-chip not-mprotect guard (hardening). [UPDATE: smoke-prove DONE — B2 runs end-to-end; guard added.]

## Audit 8 — 2026-07-01, thesis + abst_Takumi2025 coherence pass to the new story
Mode: formative. Active-reader coherence audit (agent a561ff720091b11bb) mapped 3 blockers + coherence items; FIXES APPLIED and committed.
- Blocker 1 (family missing) FIXED (commit fab5645): §5 adds FP192_MUL + FP192_POW_RES as 2nd/3rd interface instances (all three run), interface paragraph rewritten, measured-vs-demonstrated line stated; §6 adds "already-served case (trace area)" subsubsection (B2 does-not-pay, 382 vs 261 FieldOpCols; execute misleads 17.9x) completing the two-outcome criterion demonstration + paying off §5's forward-reference.
- Blocker 2 (abst old-story) FIXED (commit fe16aae): retitled to criterion; "arithmetic mismatch"/"agility tax"/"precompile paradox" -> field-mismatch tax + criterion; family reconciled with §5; 192-vs-199 fixed; wall demoted to secondary.
- Blocker 3 (§2 criterion-gap unnamed) FIXED (fab5645): criterion named PRIMARY gap; FP192_MUL reconciled with the "no bigint circuit" line.
- Coherence items: §4 dropped "empirically on the matched side" overclaim (matches §6); §8 dropped "rest of thesis rests on" the wall.
- BUILD: thesis latexmk (platex) exit 0, 102pp, 0 undefined refs/citations; abst body compiles (uplatex, 2pp; biber_thin wrapper pre-existing/unrelated).
- REMAINING: A7 orphaned tikz substrate_compare.tex "32.5 min" (orphaned, not \input; low); Gap-2 field-width sweep pending (will fold into §4/§6 criterion predictiveness); independent active-reader re-verify dispatched.
- RE-VERIFY (agent a6616fd43fc7473d0, 14 files): all 6 coherence checks PASS, NO remaining blocker — thesis + abst read as one criterion-led story. Residuals fixed: §6 "two measured no-pay reasons" -> "one prove-relevant no-pay (already-served) + execute-mode necessity (matched-field), prove-mode ℓ=1 open"; §6 bridge at matched-field control; §8 "central deployability"->"principal, secondary to the criterion"; abst 03 "arithmetic mismatch"->field-mismatch tax; A7 tikz 32.5->14.25. Thesis rebuild exit 0, 102pp, 0 undefined.
- GAP-2 SWEEP (agent a2605631e317881e1): apparatus-dependent. The pre-registered num_bigint forecast was FALSIFIED (b=0.79, non-monotone; heap alloc + division dominate), but on the limb-schoolbook multiply the criterion actually models, the ℓ-dependence is CONFIRMED (b=1.30, 4-point curve ℓ=2..8, in the [ℓ,ℓ²] band; Fp192 wrapper within 1.8% of keystone). INTEGRITY: the schoolbook apparatus was chosen AFTER the num_bigint forecast failed -> NOT fully held-out. HELD for Operator framing (route 1 transparent report vs route 2 re-pre-register). Numbers: docs/measurements/gap2_sweep_20260701/RESULT.md.
