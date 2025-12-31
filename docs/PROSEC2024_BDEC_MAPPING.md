# ProSec2024 BDEC ↔ Code Mapping (vc-pqc)

This note is intended to make the **implementation-to-spec traceability** explicit for a thesis write‑up.
It maps the algorithms/variables from the ProSec 2024 BDEC paper (`references/ProSec2024.pdf`) to the
actual functions/types in this repository, and lists the **assumptions and deltas** you can safely claim.

## Scope

- **Loquat**: treated as the underlying signature scheme implementation (assumed correct/validated separately).
- **Aurora**: used as the zkSNARK back-end for BDEC proofs.
- **BDEC layer**: implemented in `src/bdec/mod.rs` and exercised by `src/bin/bdec_demo.rs`.

## Algorithm mapping (paper → code)

| Paper algorithm | Code entrypoint |
|---|---|
| Setup | `bdec_setup(lambda, max_attributes)` |
| PriGen | `bdec_prigen(system)` |
| NymKey | `bdec_nym_key(system, user_keypair)` |
| CreGen | `bdec_issue_credential(system, user_keypair, pseudonym, attributes)` |
| CreVer | `bdec_verify_credential(system, credential)` |
| ShowCre (paper-aligned) | `bdec_show_credential_paper(system, user_keypair, credentials, disclosed_attributes)` |
| ShowVer (paper-aligned) | `bdec_verify_shown_credential_paper(system, shown, expected_verifier_pseudonym)` |
| RevCre | `bdec_revoke(system, public_key)` |
| Conditional link proof | `bdec_link_pseudonyms(system, user_keypair, old_pseudonym, new_pseudonym)` |
| Conditional link verify | `bdec_verify_link_proof(system, link)` |

## Variable/type mapping (paper notation → structs/fields)

### System parameters

- `par` → `BdecPublicParams` (inside `BdecSystem.params`)
  - `par.loquat_params` → `LoquatPublicParams`
  - `par.crs` (paper) → modelled as `BdecPublicParams.crs_digest` (hash commitment to a CRS label; Aurora itself is transparent in this PoC implementation)
  - `par.aurora_params` → `AuroraParams`

### Keys

- Long-term keypair `(sk_U, pk_U)` → `LoquatKeyPair` (`pk_U` is `LoquatKeyPair.public_key`)
- Pseudonym public key `ppk` (paper) → `BdecPseudonymKey.public` (32 random bytes)
- Pseudonym signature `psk` (paper) → stored as `BdecPseudonymKey.signature` (a `LoquatSignature` over `ppk`)

### Credentials

- Attribute set `A` → `Vec<String>` (`BdecCredential.attributes`)
- `h = H(A)` → `BdecCredential.attribute_hash` (computed by `hash_attributes`)
- Credential signature `c` (paper) → `BdecCredential.credential_signature` (a `LoquatSignature` over `attribute_hash`)
- Credential proof `π_c` (paper) → `BdecCredential.proof.aurora_proof`

### Shown credentials

- Disclosed subset `A↓` → `BdecShownCredentialPaper.disclosed_attributes` (canonicalised + sorted)
- `H(A↓)` → `BdecShownCredentialPaper.disclosure_hash`
- Shown signature `c_U,V` → `BdecShownCredentialPaper.shown_credential_signature`
- Show proof `π_show` → `BdecShownCredentialPaper.show_proof`
- Verifier pseudonym `ppk_U,V` → `BdecShownCredentialPaper.verifier_pseudonym.public`

## What the Aurora statement/witness correspond to

In this repo, Aurora proves satisfaction of an R1CS instance:

- **Statement**: `R1csInstance` (constraint system only; no public input vector is modelled separately).
- **Witness**: `R1csWitness` (full variable assignment excluding the constant “1” slot).

### “pk_U is hidden” (paper-style existential pk)

The BDEC layer uses the *pk-witness* circuit builder:

- `build_loquat_r1cs_pk_witness(...)` for proving (pk is in the witness assignment)
- `build_loquat_r1cs_pk_witness_instance(...)` for verifying (instance only)

This is the intended implementation strategy for “existential pk_U” in the ProSec 2024 construction.

## Explicit deltas / limitations (important for claims)

These are the key points to state clearly in the thesis:

1. **Revocation is not checked inside ZK**:
   - Current implementation checks revocation by scanning the published revoked public keys and
     calling `loquat_verify(...)` against each (see `is_signature_from_revoked_key`).
   - This matches the *semantics* of “revoked → reject”, but is not a Merkle-accumulator-in-ZK design.

2. **Hidden attributes via Merkle accumulator (paper appendix suggestion) is not implemented**:
   - Credentials currently include the full attribute list and hash it directly.
   - The ProSec appendix suggests signing a Merkle root of attributes to hide undisclosed attributes.

3. **Security theorems are inherited from the paper, not re-proved in code**:
   - What you can claim: the implementation follows the paper’s algorithm structure and we provide
     *executable validation* via end-to-end tests (including real Aurora proving/verification).
   - What you cannot claim: a machine-checked proof of the Rust code.

## Reproducibility / test commands (for thesis appendix)

### BDEC end-to-end demo

```bash
cargo run --release --bin bdec_demo --offline
```

### Conditional linkability demo

```bash
cargo run --release --bin bdec_link_demo --offline
```

### Fast tests

```bash
cargo test --offline
```

### End-to-end Aurora tests (slow)

```bash
cargo test --release -- --ignored
```

### Optional harnesses (feature-gated)

```bash
# SNARK harness tests
cargo test --release --features snark_harness --test snark_harness

# EUF-CMA harness tests
cargo test --release --features euf_cma_harness --test euf_cma
```














