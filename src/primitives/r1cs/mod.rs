use crate::signatures::loquat::errors::{LoquatError, LoquatResult};
use crate::signatures::loquat::field_utils::{F, field_to_bytes};
use serde::{Deserialize, Serialize};

/// Stage-2 parallel R1CS layer over PLUM's `Fp192` field (Griffin-Fp192
/// permutation gadget). Independent of the Fp127-monomorphised types above.
pub mod griffin_fp192_gadget;
/// Stage-4a Merkle authentication-path verification gadget over `Fp192`,
/// reusing the Griffin-Fp192 permutation gadget as the 2-to-1 compression.
pub mod merkle_fp192_gadget;
/// Stage-4b STIR polynomial-operation gadgets over `Fp192` (Horner evaluate,
/// Lagrange interpolation, vanishing-poly evaluation, degree-correction
/// evaluation), reusing the Stage-2 `Fp192R1csBuilder` / `Fp192Var`.
pub mod poly_fp192_gadget;
/// Stage-4c-1 Griffin-Fp192 SPONGE (absorb/squeeze) + leaf/byte hash gadgets,
/// reusing the Stage-2 `griffin_fp192_permutation_circuit`. Matches the
/// software sponge `plum_griffin_sponge` / `PlumGriffinHasher::hash_bytes`.
pub mod sponge_fp192_gadget;
/// Stage 4c-2 in-circuit Fiat–Shamir challenge derivation over `Fp192`,
/// replaying PLUM's transcript with the Griffin sponge (not SHAKE256), with the
/// challenge bound to absorbed data and rejection sampling constrained.
pub mod fs_fp192_gadget;
/// Stage 4c-3b ONE STIR fold round as an R1CS gadget: composes the Merkle
/// path-verify, polynomial (Lagrange/Horner), sponge, and Fiat–Shamir gadgets to
/// bind one fold + one Merkle-checked query against the FS-committed root.
pub mod stir_round_fp192_gadget;
/// Stage 4c-3c the STIR verifier's OUT-OF-DOMAIN (OOD) consistency check and the
/// Algorithm-6 FINAL-POLYNOMIAL fiber check as R1CS gadgets, composing the
/// Stage-4b Lagrange/Horner polynomial gadgets. Matches the round-0 sumcheck-
/// identity OOD block (`verify.rs:537-560`) and the final-poly check
/// (`verify.rs:762-781`).
pub mod ood_finalpoly_fp192_gadget;
/// Stage 4c-4-sub the two STIR algebraic checks deferred by Stages 4c-3b/4c-3c:
/// (1) RATE-CORRECTION DIVISION deriving the corrected fiber values
/// `â_R'(x) = (â_R(x) − b̂_R(x))/Π(x−α)` from the Merkle-opened `â_R`
/// (pointwise form matching `verify.rs:732-760`; coefficient form matching
/// `stir::rate_correct` `stir.rs:204-237`), and (2) the ROUND-0 SUMCHECK
/// (sum-over-`H`) identity `Σ_{a∈H} g_hat(a) == z·mu + s_sum`
/// (`verify.rs:561-584`). Composes the Stage-4b poly gadgets; the quotient is
/// pinned by the polynomial / multiplication-back identity, never free.
pub mod rate_sumcheck_fp192_gadget;
/// Stage 4c-4-asm FINAL ASSEMBLY: the full Griffin-FS PLUM.Verify relation as ONE
/// R1CS, composing every Stage 2–4c-4-sub gadget in `verify.rs` order with
/// pk/message/roots as `alloc_public_input` public inputs. Gated at a reduced
/// scale; the PLUM-80 total is projected, not materialized.
pub mod plum_verify_fp192_gadget;
use sha2::{Digest, Sha256};
use std::vec::Vec;

/// Describes a single R1CS constraint `<a, z> * <b, z> = <c, z>`.
/// Coefficients are stored sparsely as `(index, coefficient)` pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csConstraint {
    pub a: Vec<(usize, F)>,
    pub b: Vec<(usize, F)>,
    pub c: Vec<(usize, F)>,
}

impl R1csConstraint {
    /// Construct from dense coefficient vectors (kept for compatibility in tests/examples).
    pub fn new(a_dense: Vec<F>, b_dense: Vec<F>, c_dense: Vec<F>) -> Self {
        Self::from_dense(a_dense, b_dense, c_dense)
    }

    pub fn from_dense(a_dense: Vec<F>, b_dense: Vec<F>, c_dense: Vec<F>) -> Self {
        let a = dense_to_sparse(a_dense);
        let b = dense_to_sparse(b_dense);
        let c = dense_to_sparse(c_dense);
        Self { a, b, c }
    }

    pub fn from_sparse(
        a_terms: Vec<(usize, F)>,
        b_terms: Vec<(usize, F)>,
        c_terms: Vec<(usize, F)>,
    ) -> Self {
        Self {
            a: compress_terms(a_terms),
            b: compress_terms(b_terms),
            c: compress_terms(c_terms),
        }
    }

    pub fn evaluate(&self, assignment: &[F]) -> LoquatResult<(F, F, F)> {
        Ok((
            sparse_inner_product(&self.a, assignment)?,
            sparse_inner_product(&self.b, assignment)?,
            sparse_inner_product(&self.c, assignment)?,
        ))
    }

    pub fn support(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        for (idx, _) in self.a.iter().chain(self.b.iter()).chain(self.c.iter()) {
            indices.push(*idx);
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }
}

/// Public statement consisting of constraint system metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csInstance {
    pub num_variables: usize,
    /// Number of variables that are public inputs (i.e., part of the verifier-visible
    /// instance vector). They occupy indices `[1, num_inputs]` of the witness vector
    /// after the implicit constant-1 slot at index 0. The remaining indices
    /// `[num_inputs+1, num_variables-1]` are private witness.
    ///
    /// `0` means "no public inputs" (legacy behavior used pre-Phase-4); the entire
    /// witness vector is private. New (Phase 4+) builders set this explicitly.
    #[serde(default)]
    pub num_inputs: usize,
    pub constraints: Vec<R1csConstraint>,
}

impl R1csInstance {
    pub fn new(num_variables: usize, constraints: Vec<R1csConstraint>) -> LoquatResult<Self> {
        if num_variables == 0 {
            return Err(LoquatError::invalid_parameters(
                "R1CS instances require at least one variable (the constant 1).",
            ));
        }
        for (idx, constraint) in constraints.iter().enumerate() {
            for (var_idx, _) in constraint
                .a
                .iter()
                .chain(constraint.b.iter())
                .chain(constraint.c.iter())
            {
                if *var_idx >= num_variables {
                    return Err(LoquatError::invalid_parameters(&format!(
                        "constraint {} references variable {} beyond {}",
                        idx, var_idx, num_variables
                    )));
                }
            }
        }
        Ok(Self {
            num_variables,
            num_inputs: 0,
            constraints,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.num_variables.to_le_bytes());
        hasher.update(self.num_inputs.to_le_bytes());
        for constraint in &self.constraints {
            absorb_sparse_row(&mut hasher, &constraint.a);
            absorb_sparse_row(&mut hasher, &constraint.b);
            absorb_sparse_row(&mut hasher, &constraint.c);
        }
        hasher.finalize().into()
    }

    pub fn is_satisfied(&self, witness: &R1csWitness) -> LoquatResult<()> {
        witness.validate(self)?;
        let z = witness.full_assignment();
        for (idx, c) in self.constraints.iter().enumerate() {
            let (az, bz, cz) = c.evaluate(&z)?;
            if az * bz != cz {
                if std::env::var("R1CS_DEBUG_FAIL").is_ok() {
                    eprintln!("\n[R1CS] first failing constraint #{idx}");
                    eprintln!("  az={az:?}");
                    eprintln!("  bz={bz:?}");
                    eprintln!("  cz={cz:?}");

                    let dump_row = |label: &str, row: &[(usize, F)]| {
                        eprintln!("  row {label} (len={}):", row.len());
                        for (var_idx, coeff) in row {
                            let val = z.get(*var_idx).copied().unwrap_or(F::zero());
                            eprintln!("    idx={var_idx:<6} coeff={coeff:?} val={val:?}");
                        }
                    };
                    dump_row("a", &c.a);
                    dump_row("b", &c.b);
                    dump_row("c", &c.c);
                }
                return Err(LoquatError::invalid_parameters(&format!(
                    "constraint {} not satisfied: ({:?})*({:?}) != ({:?})",
                    idx, az, bz, cz
                )));
            }
        }
        Ok(())
    }
}

/// Private assignment (without the constant 1 slot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csWitness {
    pub assignment: Vec<F>,
}

impl R1csWitness {
    pub fn new(assignment: Vec<F>) -> Self {
        Self { assignment }
    }

    pub fn validate(&self, instance: &R1csInstance) -> LoquatResult<()> {
        if instance.num_variables != self.assignment.len() + 1 {
            return Err(LoquatError::invalid_parameters(
                "witness length does not match instance",
            ));
        }
        Ok(())
    }

    pub fn full_assignment(&self) -> Vec<F> {
        let mut assignment = Vec::with_capacity(self.assignment.len() + 1);
        assignment.push(F::one());
        assignment.extend_from_slice(&self.assignment);
        assignment
    }
}

fn absorb_sparse_row(hasher: &mut Sha256, values: &[(usize, F)]) {
    hasher.update((values.len() as u64).to_le_bytes());
    for (idx, coeff) in values {
        hasher.update(idx.to_le_bytes());
        hasher.update(field_to_bytes(coeff));
    }
}

fn dense_to_sparse(row: Vec<F>) -> Vec<(usize, F)> {
    let mut terms = Vec::new();
    for (idx, coeff) in row.into_iter().enumerate() {
        if !coeff.is_zero() {
            terms.push((idx, coeff));
        }
    }
    compress_terms(terms)
}

fn compress_terms(mut terms: Vec<(usize, F)>) -> Vec<(usize, F)> {
    terms.sort_by_key(|(idx, _)| *idx);
    let mut out: Vec<(usize, F)> = Vec::with_capacity(terms.len());
    for (idx, coeff) in terms {
        if coeff.is_zero() {
            continue;
        }
        if let Some(last) = out.last_mut() {
            if last.0 == idx {
                last.1 += coeff;
                if last.1.is_zero() {
                    out.pop();
                }
                continue;
            }
        }
        out.push((idx, coeff));
    }
    out
}

fn sparse_inner_product(row: &[(usize, F)], assignment: &[F]) -> LoquatResult<F> {
    let mut acc = F::zero();
    for (idx, coeff) in row {
        let value = assignment.get(*idx).ok_or_else(|| {
            LoquatError::invalid_parameters("sparse inner product index out of range")
        })?;
        acc += *coeff * *value;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r1cs_roundtrip() {
        let constraint = R1csConstraint::new(
            vec![F::one(), F::one()],
            vec![F::one(), F::zero()],
            vec![F::zero(), F::one()],
        );
        let instance = R1csInstance::new(2, vec![constraint]).unwrap();
        let witness = R1csWitness::new(vec![F::one()]);
        witness.validate(&instance).unwrap();
        assert_eq!(instance.num_constraints(), 1);
        assert_eq!(instance.digest().len(), 32);
    }
}
