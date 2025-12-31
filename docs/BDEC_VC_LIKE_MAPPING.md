# BDEC to VC-like JSON Mapping

This document shows how BDEC cryptographic artifacts map to a VC-like JSON structure, based on the test implementation in `src/bdec/mod.rs::test_bdec_vc_like_credential_flow`.

## Overview

BDEC credentials are **not** JSON documents with signatures (like W3C VCs). They are tuples of cryptographic artifacts produced by the paper's algorithms. However, we can create a VC-like JSON *shape* that preserves BDEC's cryptographic meaning.

## 1. TA-Approved Credential Record (On-Chain)

This corresponds to **CreGen + CreVer + publish** in the BDEC paper.

### Rust Structure
```rust
pub struct BdecCredential {
    pub pseudonym: BdecPseudonymKey,           // (ppk_U_TA, psk_U_TA)
    pub attributes: Vec<String>,                // A
    pub attribute_hash: [u8; 32],              // h_U_TA = H(A)
    pub credential_signature: LoquatSignature,  // c_U_TA = Sig.Sign(sk_U, h_U_TA)
    pub proof: BdecCredentialProof,            // ε_c_U_TA (zkSNARK proof)
}
```

### VC-like JSON Mapping
```json
{
  "type": ["BDECApprovedCredential"],
  "id": "urn:bdec:cred:tx:0xABC...",

  "issuer": {
    "id": "did:example:TA-XYZ-University",
    "role": "TrustedAuthorityPublisher"
  },

  "issuanceDate": "2025-12-27T00:00:00Z",

  "credentialSubject": {
    "id": "bdec:ppk:<BASE64URL(ppk_U_TA)>",

    "attributes": {
      "Name": "Alice",
      "University": "XYZ University",
      "Degree": "Bachelor of Software Engineering",
      "Year": 2023,
      "GPA": "4.8/5"
    },

    "aux": {
      "attributeOrder": ["Name", "University", "Degree", "Year", "GPA"],
      "encoding": "canonical-json-v1"
    },

    "commitment": {
      "hashAlg": "H-from-Sig.pp",
      "digest": "<BASE64URL(h_U_TA)>"
    }
  },

  "bdecArtifacts": {
    "ppk_U_TA": "<BASE64URL(ppk_U_TA)>",
    "c_U_TA": "<BASE64URL(c_U_TA)>",
    "epsilon_c_U_TA": "<BASE64URL(epsilon_c_U_TA)>"
  },

  "cryptoSuite": {
    "signature": "Loquat-Crypto2024",
    "zkSNARK": "Aurora-IACR2018",
    "parRef": {
      "Sig_pp_id": "loquat:lambda128",
      "crs_id": "aurora:default",
      "circuit_id": "circuit:CreGen_v1"
    }
  }
}
```

### Key Fields Explained

- **`bdecArtifacts`**: The actual cryptographic tuple published by the TA after verification
  - `ppk_U_TA`: Pseudonym public key
  - `c_U_TA`: Credential signature on `h_U_TA`
  - `epsilon_c_U_TA`: zkSNARK proof attesting to validity

- **`commitment.digest`**: The hash `h_U_TA = H(A)` used in the signature

- **`aux`**: Critical for deterministic hashing - BDEC requires canonical encoding of attributes to avoid hash mismatches

## 2. Shown Credential / Presentation (For Verifier)

This corresponds to **ShowCre/ShowVer** in the BDEC paper.

### Rust Structure
```rust
pub struct BdecShownCredentialPaper {
    pub credentials: Vec<BdecCredential>,        // Prior approved credentials
    pub verifier_pseudonym: BdecPseudonymKey,    // (ppk_U_V, psk_U_V)
    pub disclosed_attributes: Vec<String>,        // A↓ (subset of A)
    pub disclosure_hash: [u8; 32],               // h_U_V = H(A↓)
    pub shown_credential_signature: LoquatSignature, // c_U_V = Sig.Sign(sk_U, h_U_V)
    pub show_proof: AuroraProof,                 // ε_c_U_V (zkSNARK proof)
    pub revocation_proof: Option<BdecRevocationProof>,
}
```

### VC-like JSON Mapping
```json
{
  "type": ["BDECShownCredential"],
  "id": "urn:bdec:shown:local:1234",

  "holderPseudonym": {
    "id": "bdec:ppk:<BASE64URL(ppk_U_V)>",
    "forVerifier": "did:example:Company-V"
  },

  "disclosedAttributes": {
    "Degree": "Bachelor of Software Engineering",
    "University": "XYZ University"
  },

  "aux": {
    "attributeOrder": ["Degree", "University"],
    "encoding": "canonical-json-v1"
  },

  "commitment": {
    "hashAlg": "H-from-Sig.pp",
    "digest": "<BASE64URL(h_U_V)>"
  },

  "bdecArtifacts": {
    "c_U_V": "<BASE64URL(c_U_V)>",
    "epsilon_c_U_V": "<BASE64URL(epsilon_c_U_V)>"
  },

  "evidence": {
    "approvedCredentialRefs": [
      "urn:bdec:cred:tx:0xTA1...",
      "urn:bdec:cred:tx:0xTA2..."
    ]
  },

  "revocation": {
    "status": "not_revoked",
    "proofType": "sparse-merkle-zk",
    "root": "<BASE64URL(revocation_root)>",
    "depth": 16
  },

  "cryptoSuite": {
    "signature": "Loquat-Crypto2024",
    "zkSNARK": "Aurora-IACR2018",
    "parRef": {
      "Sig_pp_id": "loquat:lambda128",
      "crs_id": "aurora:default",
      "circuit_id": "circuit:ShowCre_v1"
    }
  }
}
```

### Key Fields Explained

- **`holderPseudonym`**: The verifier-specific pseudonym `ppk_U_V` (different from TA pseudonym for unlinkability)

- **`disclosedAttributes`**: Only the subset `A↓` disclosed to this verifier

- **`evidence.approvedCredentialRefs`**: References to prior TA-approved credentials that this presentation builds upon

- **`revocation`**: Optional ZK proof of non-revocation (user's `pk_U` not in revocation list)

## 3. Minimal Paper API (New Addition)

The new `BdecPaperCredential` provides an even more minimal format:

### Rust Structure
```rust
pub struct BdecPaperCredential {
    pub pseudonym_public: Vec<u8>,      // ppk
    pub message_commitment: [u8; 32],    // h
    pub aurora_commitment: [u8; 32],     // c
    pub aurora_proof: AuroraProof,       // ε
}
```

### VC-like JSON Mapping
```json
{
  "type": ["BDECPaperCredential"],
  "id": "bdec:ppk:<BASE64URL(ppk)>",

  "commitment": {
    "message": "<BASE64URL(h)>",
    "aurora": "<BASE64URL(c)>"
  },

  "proof": {
    "type": "AuroraProof",
    "value": "<BASE64URL(ε)>"
  }
}
```

## 4. Complete Flow Test Output

Running `cargo test --lib bdec::paper_api_tests::test_bdec_vc_like_credential_flow -- --nocapture` produces:

```
=== BDEC VC-like Credential Flow Test ===

Step 1: BDEC System Setup
  ✓ System parameters initialized
  ✓ Loquat params: λ=128, max_attributes=5

Step 2: User Key Generation (PriGen)
  ✓ Generated (sk_U, pk_U)
  ✓ pk_U length: 128 bits

Step 3: Pseudonym Generation (NymKey for TA)
  ✓ Generated pseudonym (ppk_U_TA, psk_U_TA)
  ✓ ppk_U_TA length: 40 bytes

Step 4: Credential Generation (CreGen)
  Attributes:
    - Name:Alice
    - University:XYZ University
    - Degree:Bachelor of Software Engineering
    - Year:2023
    - GPA:4.8/5
  ✓ Generated credential signature c_U_TA
  ✓ Computed attribute hash h_U_TA
  ✓ Generated zkSNARK proof ε_c_U_TA

  VC-like structure mapping:
  {
    "type": ["BDECApprovedCredential"],
    "issuer": { "id": "did:example:TA-XYZ-University" },
    "credentialSubject": {
      "id": "bdec:ppk:a1b2c3d4...",
      "attributes": { ... 5 attributes ... },
      "commitment": {
        "digest": "e5f6a7b8..."
      }
    },
    "bdecArtifacts": {
      "ppk_U_TA": "a1b2c3d4...",
      "c_U_TA": "<signature bytes>",
      "epsilon_c_U_TA": "<proof bytes>"
    }
  }

Step 5: Credential Verification (CreVer)
  ✓ TA verified credential successfully
  ✓ Ready for on-chain publication

Step 6: Presentation Generation (ShowCre)
  Disclosed attributes:
    - Degree:Bachelor of Software Engineering
    - University:XYZ University
  ✓ Generated verifier pseudonym ppk_U_V
  ✓ Computed disclosure hash h_U_V
  ✓ Generated shown credential signature c_U_V
  ✓ Generated zkSNARK proof ε_c_U_V

  Shown credential VC-like structure:
  {
    "type": ["BDECShownCredential"],
    "holderPseudonym": {
      "id": "bdec:ppk:x9y8z7w6...",
      "forVerifier": "did:example:Company-V"
    },
    "disclosedAttributes": { ... 2 attributes ... },
    "commitment": {
      "digest": "c4d5e6f7..."
    },
    "bdecArtifacts": {
      "c_U_V": "<signature bytes>",
      "epsilon_c_U_V": "<proof bytes>"
    }
  }

Step 7: Presentation Verification (ShowVer)
  ✓ Verifier confirmed presentation validity
  ✓ Pseudonym ppk_U_V verified
  ✓ Disclosed attributes confirmed

Step 8: Revocation Test
  ✓ User pk_U added to revocation list
  ✓ Revoked credential correctly rejected

=== Test Complete ===
All BDEC operations verified successfully!

Key insights:
  • Credentials contain cryptographic artifacts (ppk, c, ε), not JSON signatures
  • Attributes are hashed into commitments (h = H(A))
  • zkSNARK proofs bind pseudonyms to hidden pk_U
  • Selective disclosure via commitment to H(A↓)
  • Revocation via pk_U publication (privacy-preserving until revoked)
```

## 5. Important BDEC-Specific Invariants

When mapping to VC-like JSON, **preserve these BDEC properties**:

1. **The `proof` is NOT a signature over the JSON**
   - It's a zkSNARK proof `ε` for the BDEC relation
   - The actual signatures are `c_U_TA` and `c_U_V`

2. **Commitments must use canonical encoding**
   - Hash mismatches break verification
   - The `aux.encoding` field specifies the deterministic encoding scheme

3. **Revocation mechanism differs from VCs**
   - BDEC publishes `pk_U` to a list (privacy-preserving until revoked)
   - VC-like `credentialStatus` can reference this list

4. **Multiple pseudonyms for unlinkability**
   - `ppk_U_TA` for TA (credential issuance)
   - `ppk_U_V` for verifier (presentation)
   - Both bound to same hidden `pk_U` via zkSNARK

5. **ShowCre proves conjunction of multiple signatures**
   - One zkSNARK proves validity of TA credentials + verifier pseudonym + disclosure signature
   - All under the same hidden `pk_U`

## 6. API Usage Examples

### Creating a Credential
```rust
let system = bdec_setup(128, 5)?;
let user = bdec_prigen(&system)?;
let pseudonym_ta = bdec_nym_key(&system, &user)?;

let attributes = vec![
    "Name:Alice".to_string(),
    "Degree:BSE".to_string(),
];

let credential = bdec_issue_credential(
    &system,
    &user,
    &pseudonym_ta,
    attributes,
)?;

// credential now contains (ppk_U_TA, c_U_TA, ε_c_U_TA, h_U_TA, A)
```

### Verifying a Credential
```rust
let valid = bdec_verify_credential(&system, &credential)?;
assert!(valid);
```

### Creating a Presentation
```rust
let disclosed = vec!["Degree:BSE".to_string()];

let shown = bdec_show_credential_paper(
    &system,
    &user,
    &[credential],
    disclosed,
)?;

// shown contains (ppk_U_V, c_U_V, ε_c_U_V, h_U_V, A↓)
```

### Verifying a Presentation
```rust
let valid = bdec_verify_shown_credential_paper(
    &system,
    &shown,
    &shown.verifier_pseudonym.public,
)?;
assert!(valid);
```

### Using the Minimal Paper API
```rust
let signature = loquat_sign(message, &user, &system.params.loquat_params)?;

let paper_cred = bdec_paper_create_credential(
    &system,
    &user,
    message,
    &signature,
)?;

// paper_cred contains only (ppk, h, c, ε)

let valid = bdec_paper_verify_credential(&system, &paper_cred, message)?;
assert!(valid);
```

## 7. Next Steps

To fully implement the VC-like format:

1. **Define canonical encoding spec** for `aux.encoding = "canonical-json-v1"`
   - Key ordering
   - Numeric normalization
   - String escaping rules

2. **Add serialization/deserialization** helpers
   - Convert between Rust structs and JSON
   - Handle Base64URL encoding

3. **Implement storage format**
   - On-chain: `(ppk, c, ε, h)` + metadata
   - Off-chain: Full attributes with proofs

4. **Add revocation status checking**
   - Query blockchain revocation list
   - Optional: ZK non-membership proofs

## References

- BDEC Paper: *Enhancing Learning Credibility via Post-Quantum Digital Credentials* (ProSec 2024)
- Loquat: *Post-Quantum Signatures from Legendre PRFs* (Crypto 2024)
- W3C VC Data Model: https://www.w3.org/TR/vc-data-model-2.0/
- W3C VC Data Integrity: https://www.w3.org/TR/vc-data-integrity/
