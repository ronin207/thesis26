use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{F, field_to_bytes};
use serde::{Deserialize, Serialize};
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
            constraints,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.num_variables.to_le_bytes());
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
