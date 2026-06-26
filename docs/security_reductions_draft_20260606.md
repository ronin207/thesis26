# Explicit security reductions — draft for proof-checker (NOT committed)

Goal: rewrite §055's three reductions to explicit-skeleton form + fix the error-term accounting,
respecting how AC ← (signature, zkSNARK) compose and how the zkVM instantiates the zkSNARK.
Grounded in BDEC's own proofs (references/bdec_full.txt:984-1110), read directly:
- Thm 1 (unf): A → zkSNARK knowledge extractor → extracted psk is a signature EU-CMA forgery; loss = knowledge error.
- Thm 2 (anon): simulator S with black-box S_σ (signature sim) for pseudonym key + credential, then S_Π (proof sim) for the proof; "perfect ZK of sig AND zkSNARK ⇒ perfect anonymity".
- Thm 3 (unlink): same simulator structure (S_σ then S_Π). BDEC's unlink GAME (bdec_full.txt:479-501) forwards a SINGLE credential c^b and asks which pseudonym key b — a one-transcript guess.

zkVM instantiation: Π = the zkVM (knowledge-soundness ε_KS, zero-knowledge ε_ZK); the precompile adds
ε_AIR (premise T2); PLUM provides EU-CMA (ε_EUF, T-implicit) and a transcript simulator (ε_sZK, T4).

## DRAFT R-unf (re-instantiation of BDEC Thm 1)
Let 𝒜 be PPT against zkVM-BDEC unforgeability. CreVer invokes Π_vm.Verify. On 𝒜's output (x*,π*)
with Π_vm.Verify=1 and x* outside the issued set: by knowledge-soundness the extractor ℰ yields
w*=(pk_U*, psk*) except w.p. ε_KS; the extracted Griffin transitions equal the reference permutation
except w.p. ε_AIR (T2); then psk* is a PLUM signature on an un-signed message, i.e. a PLUM EU-CMA
forgery. Construct ℬ_EUF = (run 𝒜; extract; output psk*). Then
  Adv^unf_zkVM-BDEC(𝒜) ≤ ε_EUF + ε_KS + ε_AIR.        [no Adv^unf_BDEC term]

## DRAFT R-anon (re-instantiation of BDEC Thm 2; two-hybrid)
Let 𝒜 be the anonymity distinguisher, Adv = |Pr[b'=b]-1/2|.
  H0: real challenge showing for cred_b.
  H1: pseudonym key + credential produced by the PLUM signature simulator S_σ (no sk).  |H0-H1| ≤ ε_sZK (T4).
  H2: proof produced by the zkVM ZK simulator S_Π (no witness).                          |H1-H2| ≤ ε_ZK.
In H2 the challenge is independent of b ⇒ Pr[b'=b]=1/2. Hence
  Adv^anon_zkVM-BDEC(𝒜) ≤ ε_ZK + ε_sZK.               [ε_AIR does NOT enter; no Adv^anon_BDEC term]

## DRAFT R-unlink (re-instantiation of BDEC Thm 3) — FACTOR FLAGGED
Same two-hybrid simulator. The factor depends on the GAME:
  (i) BDEC's own unlink game (single credential c^b, guess pseudonym key): one transcript ⇒
      Adv^unlink_zkVM-BDEC(𝒜) ≤ ε_ZK + ε_sZK.
  (ii) the two-transcript same-vs-independent game (thesis §3 A5 restatement): simulate BOTH transcripts ⇒
      Adv^unlink_zkVM-BDEC(𝒜) ≤ 2(ε_ZK + ε_sZK).

## QUESTIONS FOR PROOF-CHECKER (adjudicate before commit)
Q-A. Is dropping Adv^•_BDEC(ℬ) from all three bounds (re-instantiation framing) correct and preferable to
   the current black-box "Adv^•_BDEC + errors" framing, which double-counts (Adv^unf_BDEC already ≤ ε_EUF+ε_KS
   by BDEC Thm 1)? Or should the thesis keep Adv^•_BDEC and instead state the errors as DIFFERENCES
   (zkVM-vs-Aurora)? Which is sound and which matches convention for a "substitute-the-substrate" thesis?
Q-B. Unlinkability game/factor: must the thesis match BDEC's single-credential unlink game (⇒ 1×, ε_ZK+ε_sZK,
   "BDEC Thm 3" cited faithfully), or keep the two-transcript same-vs-independent notion (⇒ 2×, but then it is
   a DIFFERENT/stronger notion not literally BDEC Thm 3 and must be proved directly, not inherited)? Which is
   correct, and is §3's A5 unlinkability definition consistent with whichever §055 uses?
Q-C. R-unf: is it correct that ε_AIR enters unforgeability (a malformed Griffin trace lets a false witness be
   extracted) but NOT anonymity/unlinkability (honest showings)? Confirm ε_AIR placement per property.
Q-D. R-anon/unlink: is the hybrid order (S_σ then S_Π) and the per-hop bound (ε_sZK, ε_ZK) faithful to BDEC
   Thm 2/3, and is ε_KS correctly ABSENT from anon/unlink (no extraction)?
Q-E. Any layer-conflation or new soundness issue introduced by these rewrites? Cite file:line.
