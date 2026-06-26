# Boundless proving — handoff

Goal: get the **prove + Groth16 (zero-knowledge) results** the M5 Pro can't
produce locally, by outsourcing to the Boundless proving network. These are
**network** results, not consumer-PC results — see "Thesis framing" below.

## What is ready (built + locally validated)

The export tool `bdec_boundless_export` produced and **executor-validated** the
two files each Boundless request needs (guest ELF + serde-encoded stdin):

| relation | dir | ELF | input | execute cycles | image id (hex, first 16) |
|---|---|---|---|---|---|
| plum-verify (smoke) | `boundless_export/plum_verify/` | 569 KB | 293 KB | 4.70e9 | `49778325698e6c5e` |
| cregen (headline) | `boundless_export/cregen/` | 584 KB | 426 KB | 9.40e9 | `9ce43cdb82c3385e` |
| showcre k=2 | run the tool | — | — | ~1.88e10 | — |

Re-export / add ShowCre:
```bash
VC_PQC_SKIP_LIBIOP=1 BDEC_RELATION=showcre BDEC_SHOWCRE_K=2 \
  cargo run --release --manifest-path platforms/zkvms/risc0/host/Cargo.toml \
  --bin bdec_boundless_export
```
Each `boundless_export/<relation>/manifest.txt` has the full image id and the
request command. "Validated locally" means the executor accepted the exact
`input.bin` bytes, so a *paid* submission will not be wasted on a malformed input.

## What you run (wallet / funding / submit — I cannot do these)

1. **Throwaway wallet.** Create a fresh wallet (e.g. `cast wallet new`) and keep
   its private key. Use a throwaway — never a key with real funds.
2. **Sepolia funds.** Fund it from a Sepolia ETH faucet (free testnet ETH).
3. **RPC URL.** Free Alchemy Sepolia endpoint.
4. **Storage.** A Pinata JWT (free tier) or S3/GCS — Boundless uploads the ELF
   and input here because both exceed the 1 kB inline limit (and are well under
   the 50 MB cap).
5. **Submit** (this signs an on-chain tx and pays):
   ```bash
   export RPC_URL=...  PRIVATE_KEY=...  PINATA_JWT=...
   # smallest first, to smoke-test the whole submit->prove->Groth16 pipeline.
   # PRIVATE_KEY must be set WITHOUT the 0x prefix. Prices are in wei (Sepolia
   # test ETH); tune up if no prover picks it up. --program auto-uploads the ELF
   # via the storage provider. Do NOT add --encode-input: input.bin is already
   # serde-encoded by the export tool.
   boundless request submit-offer \
     --program    boundless_export/plum_verify/guest.elf \
     --input-file boundless_export/plum_verify/input.bin \
     --proof-type groth16 \
     --storage-provider pinata --pinata-jwt "$PINATA_JWT" \
     --min-price 1000000000000000 --max-price 50000000000000000 \
     --timeout 900 --lock-timeout 600 \
     --wait
   ```
   (Verified against boundless-cli 0.14.1.) Retrieve afterwards with
   `boundless request get-proof <ID>` (journal + seal) and
   `boundless request verify-proof <ID>`. The per-relation `manifest.txt` files
   embed an earlier draft command — this doc is the authoritative one.

## Record these (the quantifiable results)

For each relation: **prover wall-clock on Boundless**, the **Groth16 receipt /
seal size**, whether on-chain verification against the **image id** succeeds, and
the **price paid**. That gives the deployment-path numbers.

## Cost / feasibility flag

Boundless prices per cycle. These are large jobs (4.70e9 → 1.88e10 guest cycles),
so on **mainnet** the cost is real and scales with cycles — possibly significant.
Do everything on **Sepolia testnet first** (faucet ETH, nominal cost) to validate
the pipeline and obtain a first Groth16 receipt + metrics. Start with
`plum-verify` (cheapest), then `cregen`, then `showcre`. A prover may decline the
largest jobs on testnet; if so, that itself is a recordable limit.

## Thesis framing (keep the PC story the headline)

Boundless provers are powerful remote machines — the opposite of the M5 Pro. So
report these as a **deployment alternative**, not as consumer-PC numbers:
"On consumer hardware (M5 Pro, 24 GB) the prove and the zero-knowledge wrap are
infeasible (the frontier finding). Outsourced to the Boundless proving network,
the Groth16-wrapped proof completes — proving time X, receipt size Y, cost Z —
demonstrating that the construction is end-to-end realisable via outsourced
proving." This closes the "we never obtained a ZK proof" gap without diluting the
consumer-hardware frontier.

## What the proof attests (unchanged)

The Groth16 receipt proves the guest's relation — the `k+2` (ShowCre) or 2
(CreGen) signature verifications under the hidden `pk_U` — in zero knowledge.
The journal commits only the boolean result and counters; `pk_U` and the
signatures stay private. It does **not** prove the presentation predicate φ
(verifier-side). The image id binds the receipt to the exact guest.
