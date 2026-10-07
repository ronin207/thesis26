# Intro state-of-the-art passage — DRAFTED, then REMOVED (2026-07-19)

Status: drafted per Sako's 2026-07-17 request ("the introduction section should provide more
information on state of the art"), inserted at end of §1.2, then REMOVED at Operator's call
because it near-duplicates §2:38's own five-clause gap paragraph. Preserved here for reinsertion
if Sako answers the cover-note question with "put it in §1".

If reinserted, ALSO apply the §2:38 trim (drop its five-clause list, keep the summary + gap
sentence + the unreported-dimension content) so the elimination is performed once:
§2:38 opening → "The prior work has thus reached every piece of the problem and none of the
whole, the elimination Section~\ref{sec:intro} states line by line. No prior work runs an
algebraic-hash post-quantum anonymous credential inside a zkVM to learn whether it runs at all,
at what proving cost, and with which security properties intact."

Cover-note line (pointed question + proposed answer, her preferred form):
"State of the art: treated fully in Section 2 (with the positioning table); I kept it out of
Section 1 to avoid stating the same elimination twice — is a pointer from the introduction
sufficient, or do you want a compressed version in §1?"

## The passage (insert after §1.2's "This is the tension…" paragraph; all cite keys exist in ref.bib)

That question is not answered by any existing route; each stops short of it in a different place. Lattice-based constructions deliver a post-quantum anonymous credential directly, but as bespoke protocols with large proofs and keys, not as an existing signature's verification run as a program~\cite{jeudy2023lattice}. The static-circuit route proves such a signature inside a fixed circuit, and BDEC together with later measured constructions shows that it works~\cite{10.1007/978-981-96-0957-4_3,feneuil2025capss}; but every change to the predicate or the signature recompiles and re-audits the circuit. Post-quantum signatures have been run inside zkVMs, but they are standardised or hash-based ones, run without a custom precompile, and run as bare signatures rather than as credentials~\cite{s2morrow2025,saygan2026happier,kota2025dilithiumzk}. Precompiles are an established acceleration pattern, yet none targets a large-prime-field algebraic hash, and existing tools decide whether one pays only after it is built~\cite{powdr2025autoprecompiles,vapps2025}. What security a zkVM receipt itself carries is known fact by fact, the default receipt not being zero-knowledge and the available wraps being pairing-based, but these facts have not been assembled into an obstruction for a post-quantum credential~\cite{cryptoeprint:2024/1037,succinct2025prooftypes}. No prior work runs an algebraic-hash post-quantum anonymous credential inside a zkVM on consumer hardware, to learn whether it runs at all, at what proving cost, and with which security properties intact; Section~\ref{sec:related} reviews each of these lines in full.

Trace: sentence-by-sentence to §2:21 / :26 / :29 / :32 / :35 / :38+:2. Zero new names (BDEC
already introduced in §1.1; CAPSS rides as unnamed citation).
