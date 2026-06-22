//! Griffin-Fp192 permutation as an R1CS constraint gadget (Stage 2).
//!
//! This is a **parallel** R1CS layer over PLUM's `Fp192` field. It does NOT
//! reuse `crate::primitives::r1cs::{R1csInstance, R1csWitness}` — those are
//! monomorphised to the Loquat 127-bit field `F`
//! (`src/signatures/loquat/field_utils.rs`). Swapping that layer to `Fp192`
//! would break the entire working Loquat circuit and its tests, so instead we
//! ship a self-contained Fp192 R1CS builder + satisfaction checker here.
//!
//! The constraint STRUCTURE is ported verbatim from Loquat's
//! `griffin_permutation_circuit` (`src/signatures/loquat/r1cs_circuit.rs`
//! ~:5794): nonlinear layer (forward + inverse S-box, quadratic factors),
//! linear MDS layer, additive round constants. Every constant and parameter
//! is replaced with PLUM Griffin-Fp192's values, sourced from
//! [`crate::primitives::hash::griffin_p192::plum_griffin_params`].
//!
//! Material differences from the Loquat port:
//!   - S-box exponent `d = 3` (Loquat: 5), inverse via witness + `y^3 = base`.
//!   - `d_inv` is a 199-bit `BigUint`; the inverse-S-box witness value is
//!     computed with `Fp192::pow_biguint`, NOT a `u128` exponent.
//!   - `lambda = i - 1` in the linear form is built with `Fp192::from_u64`,
//!     never coerced through `u128` (the prime exceeds 128 bits).

use num_bigint::BigUint;

use crate::primitives::field::p192::Fp192;
use crate::primitives::hash::griffin_p192::{
    PlumGriffinParams, PLUM_GRIFFIN_STATE_WIDTH, plum_griffin_params,
};

// ---------------------------------------------------------------------------
// Minimal Fp192 R1CS types (parallel to primitives::r1cs over F)
// ---------------------------------------------------------------------------

/// A single R1CS constraint `<a, z> * <b, z> = <c, z>`, sparse `(idx, coeff)`.
#[derive(Debug, Clone)]
pub struct Fp192Constraint {
    pub a: Vec<(usize, Fp192)>,
    pub b: Vec<(usize, Fp192)>,
    pub c: Vec<(usize, Fp192)>,
}

/// A complete Griffin-Fp192 R1CS system together with the satisfying witness
/// produced by the gadget while it built the constraints.
///
/// `assignment[0]` is the constant-1 slot; the full assignment vector `z`
/// indexes directly into it (index 0 == 1).
#[derive(Debug, Clone)]
pub struct Fp192R1cs {
    pub num_variables: usize,
    /// Number of variables that are public inputs (the verifier-visible
    /// INSTANCE). They occupy assignment indices `[1, num_inputs]` immediately
    /// after the constant-1 slot at index 0; indices
    /// `[num_inputs + 1, num_variables - 1]` are private witness.
    ///
    /// `0` means "no public inputs" — the legacy all-private behaviour every
    /// Stage 2/3/4a/4b/4c gadget relied on before this boundary existed. This
    /// mirrors `crate::primitives::r1cs::R1csInstance::num_inputs` for the
    /// Fp127 Loquat stack (mod.rs ~:91).
    pub num_inputs: usize,
    pub constraints: Vec<Fp192Constraint>,
    /// Full assignment including the constant-1 slot at index 0.
    pub assignment: Vec<Fp192>,
}

impl Fp192R1cs {
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// The verifier-visible public-input (INSTANCE) vector: assignment indices
    /// `[1, num_inputs]`. Empty when `num_inputs == 0`. Distinct from the
    /// constant-1 slot at index 0 and from the private witness tail.
    pub fn public_inputs(&self) -> &[Fp192] {
        &self.assignment[1..=self.num_inputs.min(self.num_variables.saturating_sub(1))]
    }

    /// The private-witness tail: assignment indices `[num_inputs + 1, end)`.
    /// Excludes the constant-1 slot (index 0) and the public-input prefix.
    pub fn private_witness(&self) -> &[Fp192] {
        &self.assignment[(1 + self.num_inputs).min(self.assignment.len())..]
    }

    /// Check every constraint against the stored assignment. Returns
    /// `Err(idx)` for the first failing constraint, `Ok(())` if all hold.
    pub fn check_satisfied(&self) -> Result<(), usize> {
        for (i, con) in self.constraints.iter().enumerate() {
            let az = inner_product(&con.a, &self.assignment);
            let bz = inner_product(&con.b, &self.assignment);
            let cz = inner_product(&con.c, &self.assignment);
            if az * bz != cz {
                return Err(i);
            }
        }
        Ok(())
    }
}

fn inner_product(row: &[(usize, Fp192)], z: &[Fp192]) -> Fp192 {
    let mut acc = Fp192::zero();
    for (idx, coeff) in row {
        acc = acc + coeff.clone() * z[*idx].clone();
    }
    acc
}

// ---------------------------------------------------------------------------
// Builder + FieldVar (parallel to R1csBuilder / FieldVar over F)
// ---------------------------------------------------------------------------

/// One wire in the Fp192 R1CS: its variable index plus its concrete value.
#[derive(Clone)]
pub struct Fp192Var {
    idx: usize,
    value: Fp192,
}

impl Fp192Var {
    pub fn index(&self) -> usize {
        self.idx
    }
    pub fn value(&self) -> &Fp192 {
        &self.value
    }
}

/// Constraint-system builder over `Fp192`.
///
/// Variable 0 is the implicit constant-1 slot. `alloc` returns indices
/// `>= 1`. This mirrors the Loquat `R1csBuilder` convention (its
/// `full_assignment` prepends `F::one()` at index 0; here we hold the `1`
/// directly at `assignment[0]`).
pub struct Fp192R1csBuilder {
    assignment: Vec<Fp192>,
    constraints: Vec<Fp192Constraint>,
    /// Count of public-input (INSTANCE) wires allocated so far. Maintained as a
    /// clean prefix: a public input may only be allocated while NO non-public
    /// wire exists yet, so the public set is exactly `[1, num_inputs]`.
    num_inputs: usize,
}

impl Fp192R1csBuilder {
    pub fn new() -> Self {
        // Index 0 is the constant-1 slot.
        Self {
            assignment: vec![Fp192::one()],
            constraints: Vec::new(),
            num_inputs: 0,
        }
    }

    /// Allocate a fresh witness variable carrying `value`. Returns its index.
    fn alloc(&mut self, value: Fp192) -> usize {
        let idx = self.assignment.len();
        self.assignment.push(value);
        idx
    }

    /// Allocate a PUBLIC-INPUT (verifier-visible INSTANCE) wire carrying
    /// `value`, recording it in the public-input prefix `[1, num_inputs]`.
    ///
    /// To keep the public set a clean prefix (matching the Loquat
    /// `R1csInstance` contract: public inputs occupy `[1, num_inputs]` right
    /// after the constant-1 slot), this MUST be called before any private wire
    /// is allocated. Panics otherwise — interleaving a public input after a
    /// private wire would silently corrupt the instance/witness split.
    ///
    /// Like `alloc_input`, the wire is a FREE witness with no constraint of its
    /// own; the caller pins it through subsequent constraints. The verifier
    /// fixing pk / message / signature-roots is exactly this allocation.
    pub fn alloc_public_input(&mut self, value: Fp192) -> Fp192Var {
        assert_eq!(
            self.assignment.len(),
            1 + self.num_inputs,
            "alloc_public_input must precede any private wire: public inputs \
             must form the clean prefix [1, num_inputs] (have {} wires, \
             num_inputs={})",
            self.assignment.len() - 1,
            self.num_inputs,
        );
        let idx = self.alloc(value.clone());
        self.num_inputs += 1;
        debug_assert_eq!(idx, self.num_inputs, "public input not at prefix index");
        Fp192Var { idx, value }
    }

    /// Enforce `(Σ a_i z_i) * (Σ b_i z_i) = (Σ c_i z_i)`.
    fn enforce(
        &mut self,
        a: Vec<(usize, Fp192)>,
        b: Vec<(usize, Fp192)>,
        c: Vec<(usize, Fp192)>,
    ) {
        self.constraints.push(Fp192Constraint { a, b, c });
    }

    /// Enforce a linear relation `(Σ terms) + constant == 0` as `lc * 1 = 0`.
    /// `constant` lands on the index-0 (constant-1) slot.
    fn enforce_linear(&mut self, terms: &[(usize, Fp192)], constant: Fp192) {
        let mut a: Vec<(usize, Fp192)> = Vec::with_capacity(terms.len() + 1);
        if !constant.is_zero() {
            a.push((0, constant));
        }
        a.extend(terms.iter().cloned());
        let b = vec![(0, Fp192::one())]; // the constant 1
        let c: Vec<(usize, Fp192)> = Vec::new(); // == 0
        self.enforce(a, b, c);
    }

    /// `left * right = out`, with `out` a fresh witness wire.
    fn mul(&mut self, left: &Fp192Var, right: &Fp192Var) -> Fp192Var {
        let prod = left.value.clone() * right.value.clone();
        let out_idx = self.alloc(prod.clone());
        self.enforce(
            vec![(left.idx, Fp192::one())],
            vec![(right.idx, Fp192::one())],
            vec![(out_idx, Fp192::one())],
        );
        Fp192Var { idx: out_idx, value: prod }
    }

    /// Enforce `left == right` (both existing wires).
    fn enforce_eq(&mut self, left: usize, right: usize) {
        // left - right == 0
        self.enforce_linear(
            &[(left, Fp192::one()), (right, -Fp192::one())],
            Fp192::zero(),
        );
    }

    /// A constant wire constrained to `value`.
    fn constant(&mut self, value: Fp192) -> Fp192Var {
        let idx = self.alloc(value.clone());
        // idx - value == 0
        self.enforce_linear(&[(idx, Fp192::one())], -value.clone());
        Fp192Var { idx, value }
    }

    /// Allocate an INPUT wire (free witness, no constraint). Used to seed the
    /// permutation state.
    pub fn alloc_input(&mut self, value: Fp192) -> Fp192Var {
        let idx = self.alloc(value.clone());
        Fp192Var { idx, value }
    }

    // ----- Public arithmetic helpers (used by sibling gadgets, e.g. the
    // Merkle path-verify gadget). These are thin wrappers over the private
    // `mul` / `alloc_bool` / `constant` / `enforce_linear` primitives so that
    // sibling modules do not reimplement constraint emission. -----

    /// `left * right = out` with `out` a fresh witness wire (one mul row).
    pub fn mul_pub(&mut self, left: &Fp192Var, right: &Fp192Var) -> Fp192Var {
        self.mul(left, right)
    }

    /// Allocate a FREE witness wire carrying `value`, with NO constraint of its
    /// own. The caller is responsible for pinning it (e.g. an inverse witness
    /// pinned by `inv*denom == 1`). Thin public wrapper over the private
    /// `alloc`; used by sibling gadgets (poly-Fp192) that need to introduce a
    /// witness whose definition is a *non-product* constraint the existing
    /// `mul_pub` (which always emits a fresh product wire) cannot express.
    pub fn alloc_witness_pub(&mut self, value: Fp192) -> Fp192Var {
        let idx = self.alloc(value.clone());
        Fp192Var { idx, value }
    }

    /// Enforce `left * right == out` between THREE EXISTING wires (one R1CS
    /// multiplication row). Unlike [`Self::mul_pub`], this does NOT allocate a
    /// new wire; it constrains wires that already exist. This is the primitive
    /// needed to pin an inverse witness: `enforce_mul_pub(inv, denom, one)`
    /// realises `inv * denom == 1` as a real constraint.
    pub fn enforce_mul_pub(&mut self, left: &Fp192Var, right: &Fp192Var, out: &Fp192Var) {
        self.enforce(
            vec![(left.idx, Fp192::one())],
            vec![(right.idx, Fp192::one())],
            vec![(out.idx, Fp192::one())],
        );
    }

    /// `out = a + b`, one linear constraint (`out - a - b == 0`).
    pub fn add_vars(&mut self, a: &Fp192Var, b: &Fp192Var) -> Fp192Var {
        let value = a.value.clone() + b.value.clone();
        let out_idx = self.alloc(value.clone());
        self.enforce_linear(
            &[
                (out_idx, Fp192::one()),
                (a.idx, -Fp192::one()),
                (b.idx, -Fp192::one()),
            ],
            Fp192::zero(),
        );
        Fp192Var { idx: out_idx, value }
    }

    /// `out = a - b`, one linear constraint (`out - a + b == 0`).
    pub fn sub_vars(&mut self, a: &Fp192Var, b: &Fp192Var) -> Fp192Var {
        let value = a.value.clone() - b.value.clone();
        let out_idx = self.alloc(value.clone());
        self.enforce_linear(
            &[
                (out_idx, Fp192::one()),
                (a.idx, -Fp192::one()),
                (b.idx, Fp192::one()),
            ],
            Fp192::zero(),
        );
        Fp192Var { idx: out_idx, value }
    }

    /// A boolean witness wire pinned by `b*b = b`.
    pub fn alloc_bool_pub(&mut self, bit: bool) -> Fp192Var {
        self.alloc_bool(bit)
    }

    /// A constant wire pinned to `value`.
    pub fn constant_pub(&mut self, value: Fp192) -> Fp192Var {
        self.constant(value)
    }

    /// Enforce `left == right` between two existing wires as ONE real linear
    /// constraint (`left - right == 0`). Public wrapper over the private
    /// `enforce_eq` so sibling gadgets (e.g. the Merkle path-verify gadget's
    /// computed-root vs. claimed-root binding) can emit the equality as an
    /// actual constraint rather than an out-of-circuit comparison.
    pub fn enforce_eq_pub(&mut self, left: &Fp192Var, right: &Fp192Var) {
        self.enforce_eq(left.idx, right.idx);
    }

    /// `base^exp` for a small `u128` exponent via square-and-multiply, each
    /// squaring/multiply a real R1CS multiplication constraint. Mirrors
    /// Loquat's `field_pow_const`.
    fn pow_const_u128(&mut self, base: &Fp192Var, exp: u128) -> Fp192Var {
        if exp == 0 {
            return self.constant(Fp192::one());
        }
        let mut result: Option<Fp192Var> = None;
        let mut current = base.clone();
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = Some(match result {
                    None => current.clone(),
                    Some(r) => self.mul(&r, &current),
                });
            }
            e >>= 1;
            if e > 0 {
                current = self.mul(&current, &current);
            }
        }
        result.expect("exp > 0 guarantees a result")
    }

    /// `base^exp` for a **large** `BigUint` exponent via left-to-right
    /// square-and-multiply, each squaring/multiply a real R1CS multiplication
    /// constraint. This is the constraint-level analogue of
    /// [`Fp192::pow_biguint`] and is the only correct path for the PLUM PRF
    /// exponent `(p-1)/256` (~191 bits), which does NOT fit in `u128` — using
    /// [`Self::pow_const_u128`] there would silently truncate the exponent and
    /// build constraints for the wrong power while still being self-consistent.
    ///
    /// Bit iteration order (MSB-down) and the `bits = exp.bits()` bound match
    /// `Fp192::pow_biguint` exactly, so the gadget's claimed output wire equals
    /// the software field exponentiation on the same input.
    fn pow_const_biguint(&mut self, base: &Fp192Var, exp: &BigUint) -> Fp192Var {
        let bits = exp.bits();
        if bits == 0 {
            return self.constant(Fp192::one());
        }
        // Mirror `Fp192::pow_biguint`: start from 1, square every step, and
        // multiply in `base` whenever the current (MSB-down) bit is set.
        let mut result = self.constant(Fp192::one());
        for i in (0..bits).rev() {
            result = self.mul(&result, &result);
            if exp.bit(i) {
                result = self.mul(&result, base);
            }
        }
        result
    }

    /// Inverse S-box `base^(d_inv)` via witness + low-degree forward check:
    /// allocate `y = base^(d_inv)` as a witness, enforce `y^d == base`.
    /// Since `gcd(d, p-1) = 1`, `x -> x^d` is a bijection so `y` is unique.
    /// Mirrors Loquat's `field_pow_inv_witness` but with a `BigUint` exponent.
    fn pow_inv_witness(
        &mut self,
        base: &Fp192Var,
        d: u64,
        d_inv: &BigUint,
    ) -> Fp192Var {
        let inv_value = base.value.pow_biguint(d_inv);
        let inv_idx = self.alloc(inv_value.clone());
        let inv_var = Fp192Var { idx: inv_idx, value: inv_value };
        let forward = self.pow_const_u128(&inv_var, d as u128);
        self.enforce_eq(forward.idx, base.idx);
        inv_var
    }

    /// Allocate a boolean wire carrying `bit` (`true`->1, `false`->0) and
    /// pin it with the constraint `b * b = b` (equivalently `b*(b-1)=0`),
    /// which holds iff `b ∈ {0, 1}`. Returns the wire.
    fn alloc_bool(&mut self, bit: bool) -> Fp192Var {
        let value = if bit { Fp192::one() } else { Fp192::zero() };
        let idx = self.alloc(value.clone());
        // b * b = b
        self.enforce(
            vec![(idx, Fp192::one())],
            vec![(idx, Fp192::one())],
            vec![(idx, Fp192::one())],
        );
        Fp192Var { idx, value }
    }

    /// Given a boolean wire `b` (already boolean-constrained) and two field
    /// constants `c0`, `c1`, produce a wire holding `b ? c1 : c0` via the
    /// affine form `out = c0 + b*(c1 - c0)`, enforced with ONE linear
    /// constraint. No multiplication is needed because the selector is the
    /// boolean wire itself and `(c1 - c0)` is a constant.
    fn select_const(&mut self, b: &Fp192Var, c0: &Fp192, c1: &Fp192) -> Fp192Var {
        let delta = c1.clone() - c0.clone();
        let value = c0.clone() + delta.clone() * b.value.clone();
        let out_idx = self.alloc(value.clone());
        // out - delta*b - c0 == 0
        self.enforce_linear(
            &[(out_idx, Fp192::one()), (b.idx, -delta)],
            -c0.clone(),
        );
        Fp192Var { idx: out_idx, value }
    }

    /// Linear form `li = (i-1)*z0 + z1 + z2`, one linear constraint.
    fn linear_form(
        &mut self,
        z0: &Fp192Var,
        z1: &Fp192Var,
        z2: &Fp192Var,
        i: usize,
    ) -> Fp192Var {
        let lambda = Fp192::from_u64((i - 1) as u64);
        let value =
            lambda.clone() * z0.value.clone() + z1.value.clone() + z2.value.clone();
        let out_idx = self.alloc(value.clone());
        // out - lambda*z0 - z1 - z2 == 0
        self.enforce_linear(
            &[
                (out_idx, Fp192::one()),
                (z0.idx, -lambda),
                (z1.idx, -Fp192::one()),
                (z2.idx, -Fp192::one()),
            ],
            Fp192::zero(),
        );
        Fp192Var { idx: out_idx, value }
    }

    pub fn finalize(self) -> Fp192R1cs {
        Fp192R1cs {
            num_variables: self.assignment.len(),
            num_inputs: self.num_inputs,
            constraints: self.constraints,
            assignment: self.assignment,
        }
    }
}

impl Default for Fp192R1csBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Griffin-Fp192 permutation gadget
// ---------------------------------------------------------------------------

/// Apply one full Griffin-Fp192 permutation to `state` in-circuit, mutating
/// `state` to hold the output wires. Ported from Loquat's
/// `griffin_permutation_circuit` with PLUM Griffin-Fp192 parameters.
pub fn griffin_fp192_permutation_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    state: &mut Vec<Fp192Var>,
) {
    for round in 0..params.rounds - 1 {
        nonlinear_layer_circuit(builder, params, state);
        linear_layer_circuit(builder, params, state);
        round_constants_circuit(builder, params, state, round);
    }
    nonlinear_layer_circuit(builder, params, state);
    linear_layer_circuit(builder, params, state);
}

fn nonlinear_layer_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    state: &mut [Fp192Var],
) {
    // Lane 0: inverse S-box.  Lane 1: forward S-box.
    state[0] = builder.pow_inv_witness(&state[0], params.d, &params.d_inv);
    state[1] = builder.pow_const_u128(&state[1], params.d as u128);

    // Lane 2: quadratic factor on li(z0, z1, 0, 2).
    let zero = builder.constant(Fp192::zero());
    let l2 = builder.linear_form(&state[0], &state[1], &zero, 2);
    let l2_sq = builder.mul(&l2, &l2);

    // poly = l2^2 + alpha*l2 + beta  (one linear constraint defining poly)
    let alpha0 = params.alphas[0].clone();
    let beta0 = params.betas[0].clone();
    let poly_value =
        l2_sq.value.clone() + alpha0.clone() * l2.value.clone() + beta0.clone();
    let poly_idx = builder.alloc(poly_value.clone());
    // poly - l2_sq - alpha*l2 - beta == 0
    builder.enforce_linear(
        &[
            (poly_idx, Fp192::one()),
            (l2_sq.idx, -Fp192::one()),
            (l2.idx, -alpha0),
        ],
        -beta0,
    );
    let poly = Fp192Var { idx: poly_idx, value: poly_value };
    state[2] = builder.mul(&state[2], &poly);

    for idx in 3..PLUM_GRIFFIN_STATE_WIDTH {
        let li = builder.linear_form(&state[0], &state[1], &state[idx - 1], idx);
        let li_sq = builder.mul(&li, &li);
        let alpha = params.alphas[idx - 2].clone();
        let beta = params.betas[idx - 2].clone();

        let poly_value =
            li_sq.value.clone() + alpha.clone() * li.value.clone() + beta.clone();
        let poly_idx = builder.alloc(poly_value.clone());
        builder.enforce_linear(
            &[
                (poly_idx, Fp192::one()),
                (li_sq.idx, -Fp192::one()),
                (li.idx, -alpha),
            ],
            -beta,
        );
        let poly = Fp192Var { idx: poly_idx, value: poly_value };
        state[idx] = builder.mul(&state[idx], &poly);
    }
}

fn linear_layer_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    state: &mut [Fp192Var],
) {
    // out_row = Σ_j M[row][j] * state[j], one linear constraint per row.
    let mut next: Vec<Fp192Var> = Vec::with_capacity(PLUM_GRIFFIN_STATE_WIDTH);
    for row in 0..PLUM_GRIFFIN_STATE_WIDTH {
        let mut out_value = Fp192::zero();
        for col in 0..PLUM_GRIFFIN_STATE_WIDTH {
            out_value = out_value
                + params.matrix[row][col].clone() * state[col].value.clone();
        }
        let out_idx = builder.alloc(out_value.clone());
        // out - Σ M[row][j]*state[j] == 0
        let mut terms: Vec<(usize, Fp192)> = Vec::with_capacity(PLUM_GRIFFIN_STATE_WIDTH + 1);
        terms.push((out_idx, Fp192::one()));
        for col in 0..PLUM_GRIFFIN_STATE_WIDTH {
            let coeff = -params.matrix[row][col].clone();
            if !coeff.is_zero() {
                terms.push((state[col].idx, coeff));
            }
        }
        builder.enforce_linear(&terms, Fp192::zero());
        next.push(Fp192Var { idx: out_idx, value: out_value });
    }
    state.clone_from_slice(&next);
}

fn round_constants_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    state: &mut [Fp192Var],
    round: usize,
) {
    for lane in 0..PLUM_GRIFFIN_STATE_WIDTH {
        let c = params.round_constants[round * PLUM_GRIFFIN_STATE_WIDTH + lane].clone();
        let var = &state[lane];
        let sum_value = var.value.clone() + c.clone();
        let sum_idx = builder.alloc(sum_value.clone());
        // sum - var - c == 0
        builder.enforce_linear(&[(sum_idx, Fp192::one()), (var.idx, -Fp192::one())], -c);
        state[lane] = Fp192Var { idx: sum_idx, value: sum_value };
    }
}

/// Build the full R1CS for one Griffin-Fp192 permutation on the given input
/// lanes, with the witness assigned by the gadget's own computation. Returns
/// the finalized system plus the output-lane variable indices (so callers can
/// read the claimed output from `r1cs.assignment`).
pub fn build_griffin_fp192_permutation(
    input: [Fp192; PLUM_GRIFFIN_STATE_WIDTH],
) -> (Fp192R1cs, [usize; PLUM_GRIFFIN_STATE_WIDTH]) {
    let params = plum_griffin_params();
    let mut builder = Fp192R1csBuilder::new();
    let mut state: Vec<Fp192Var> = input
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    griffin_fp192_permutation_circuit(&mut builder, params, &mut state);
    let out_idx: [usize; PLUM_GRIFFIN_STATE_WIDTH] =
        core::array::from_fn(|i| state[i].idx);
    (builder.finalize(), out_idx)
}

// ---------------------------------------------------------------------------
// t-th Power Residue PRF symbol-check gadget (Stage 3)
// ---------------------------------------------------------------------------
//
// Software reference: `crate::primitives::prf::power_residue::PowerResidueParams::eval`
// (`src/primitives/prf/power_residue.rs:74`), as invoked by PLUM verification
// (`src/signatures/plum/verify.rs:247`, `prf.eval(o)`). The symbol VALUE is the
// field element `symbol = shifted^((p-1)/t)` (power_residue.rs:79); the integer
// output `i ∈ [0, t)` is `dlog_ω(symbol)`, i.e. the unique `i` with
// `symbol == ω^i`, materialised by `eval` through a 256-entry HashMap lookup.
//
// In-circuit we constrain BOTH the arithmetic core AND the integer index `i`
// PLUM's verifier actually consumes (`verify.rs:247`, `prf.eval(o) as u8`):
//   1. `symbol = shifted^((p-1)/256)` via `pow_const_biguint` — every squaring
//      and mid-fold multiply is a real R1CS constraint. The exponent is a
//      ~191-bit `BigUint` (NOT `u128`), sourced verbatim from the same
//      `(p-1)/t` the software PRF uses (`DEFAULT_PARAMS.p_minus_1_over_t`).
//   2. `i = dlog_ω(symbol) ∈ [0, 256)` is recovered as EIGHT BOOLEAN WIRES
//      `b_0..b_7`, each pinned by a real `b*b=b` constraint. With exactly 8
//      bits, `i ∈ [0, 256)` is enforced structurally (no separate range proof).
//   3. `ω^i` is RECOMPUTED IN-CIRCUIT from the bits as the product
//      `Π_{k=0}^{7} (b_k ? ω^(2^k) : 1)`, where the eight `ω^(2^k)` are circuit
//      CONSTANTS derived from `DEFAULT_PARAMS.omega` (ω has order 256, so the
//      fold needs only 8 factors). Each factor is selected with one linear
//      constraint and folded with one real multiplication constraint.
//   4. `symbol == (in-circuit ω^i)` enforced as equality. Because ω has order
//      exactly 256, `i ↦ ω^i` is a bijection on `[0, 256)`, so this equation
//      has at MOST one satisfying bit pattern — the true discrete log. A
//      malicious prover who assigns the bits to any wrong `i ≠ dlog_ω(symbol)`
//      makes the equality (or a boolean) constraint fail.
//
// The host-side dlog HashMap is used ONLY to assign the bit witnesses; it is
// NOT the source of truth. The recovered index leaves the gadget as the eight
// CONSTRAINED boolean wires (plus a recomposed integer wire `Σ b_k 2^k`), so
// Stage 4 (full PLUM.Verify) consumes a constrained `i`.

use crate::primitives::prf::power_residue::PowerResidueParams;

/// Output of the PRF symbol-check gadget: the symbol field-element wire, the
/// eight CONSTRAINED boolean wires of the index `i`, a recomposed integer wire
/// `Σ b_k 2^k`, and the native `i` (for tests / convenience only — the
/// security-load-bearing value is the constrained bits, not this `u64`).
pub struct PrfSymbolVars {
    /// Wire holding `shifted^((p-1)/t)`.
    pub symbol: Fp192Var,
    /// The eight boolean wires `b_0..b_7` of `i = dlog_ω(symbol)`, LSB first.
    pub index_bits: [Fp192Var; 8],
    /// The eight select-factor wires `f_k = b_k ? ω^(2^k) : 1` (for tests that
    /// need to co-mutate a bit and its factor consistently).
    pub factors: [Fp192Var; 8],
    /// The seven fold-accumulator wires (outputs of the 7 mul constraints
    /// `acc_k = acc_{k-1} * f_k`); `fold_acc[6]` is `ω^i` itself.
    pub fold_acc: [Fp192Var; 7],
    /// Wire constrained to equal `Σ_{k} b_k · 2^k` (the integer index `i`).
    pub index: Fp192Var,
    /// Native `i` (== `Σ b_k 2^k`); convenience only, not a source of truth.
    pub i: u64,
}

/// Apply one t-th power-residue PRF symbol check to `shifted` in-circuit.
///
/// Returns a [`PrfSymbolVars`] whose `index_bits` are eight boolean-constrained
/// wires pinned to `i = dlog_ω(symbol)` by an in-circuit recomputation of
/// `ω^i` from the bits and the equality `symbol == ω^i`. The native `i` matches
/// `PowerResidueParams::eval(shifted)` exactly on a nonzero `shifted`.
///
/// NOTE: this gadget targets the `shifted != 0` case (the only case PLUM
/// verification reaches — `o_responses` are rejected when zero at
/// verify.rs:242). On `shifted == 0` the software returns `0`; we panic here
/// rather than silently mis-encode.
pub fn power_residue_prf_symbol_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PowerResidueParams,
    shifted: &Fp192Var,
) -> PrfSymbolVars {
    assert!(
        !shifted.value().is_zero(),
        "power_residue_prf_symbol_circuit: zero input is outside the gadget's domain",
    );
    assert_eq!(
        params.t, 256,
        "PRF gadget bit-decomposition assumes t = 256 (8 bits); got t = {}",
        params.t,
    );

    // (1) symbol = shifted^((p-1)/t), BigUint exponent — square-and-multiply.
    let symbol = builder.pow_const_biguint(shifted, &params.p_minus_1_over_t);

    // (2) recover i = dlog_ω(symbol) from the host dlog table — WITNESS ONLY.
    let i = *params
        .table()
        .get(symbol.value())
        .expect("PRF gadget: computed symbol not in dlog table — input not in F_p*");
    debug_assert!(i < 256, "dlog table returned i >= 256 for t = 256");

    // (3) allocate the 8 boolean bit wires of i (each pinned by b*b=b), and
    //     precompute the circuit constants ω^(2^k) for k = 0..7.
    let one = Fp192::one();
    let index_bits: [Fp192Var; 8] =
        core::array::from_fn(|k| builder.alloc_bool((i >> k) & 1 == 1));

    // (4) ω^i = Π_k (b_k ? ω^(2^k) : 1), folded with real mul constraints.
    //     Bit k contributes factor f_k = 1 + b_k*(ω^(2^k) - 1).
    let mut acc: Option<Fp192Var> = None;
    let mut factor_vars: Vec<Fp192Var> = Vec::with_capacity(8);
    let mut fold_vars: Vec<Fp192Var> = Vec::with_capacity(7);
    for k in 0..8 {
        let omega_pow_2k = params.omega.pow_u128(1u128 << k); // ω^(2^k), a constant
        let factor = builder.select_const(&index_bits[k], &one, &omega_pow_2k);
        factor_vars.push(factor.clone());
        acc = Some(match acc {
            None => factor,
            Some(a) => {
                let prod = builder.mul(&a, &factor);
                fold_vars.push(prod.clone());
                prod
            }
        });
    }
    let omega_pow_i = acc.expect("8 factors always fold to a value");
    let factors: [Fp192Var; 8] =
        core::array::from_fn(|k| factor_vars[k].clone());
    let fold_acc: [Fp192Var; 7] =
        core::array::from_fn(|k| fold_vars[k].clone());

    // (5) bind symbol == ω^i. Since ω has order 256, i ↦ ω^i is a bijection on
    //     [0,256); equality with `symbol` forces the unique correct bit pattern.
    builder.enforce_eq(symbol.idx, omega_pow_i.idx);

    // (6) recompose the integer index wire i = Σ b_k 2^k (one linear
    //     constraint) so Stage 4 can consume a single constrained `i` wire.
    let index_value = Fp192::from_u64(i);
    let index_idx = builder.alloc(index_value.clone());
    let mut terms: Vec<(usize, Fp192)> = Vec::with_capacity(9);
    terms.push((index_idx, Fp192::one()));
    for k in 0..8 {
        terms.push((index_bits[k].idx, -Fp192::from_u64(1u64 << k)));
    }
    // index - Σ b_k 2^k == 0
    builder.enforce_linear(&terms, Fp192::zero());
    let index = Fp192Var { idx: index_idx, value: index_value };

    PrfSymbolVars { symbol, index_bits, factors, fold_acc, index, i }
}

/// Wire indices exposed by [`build_power_residue_prf_symbol`] so callers and
/// tests can read/poke specific wires of the finalized system.
pub struct PrfSymbolWires {
    /// Symbol field-element wire index.
    pub symbol_idx: usize,
    /// The eight boolean bit-wire indices `b_0..b_7` (LSB first).
    pub bit_idx: [usize; 8],
    /// The eight select-factor wire indices `f_k`.
    pub factor_idx: [usize; 8],
    /// The seven fold-accumulator wire indices.
    pub fold_idx: [usize; 7],
    /// The recomposed integer-index wire `i = Σ b_k 2^k`.
    pub index_idx: usize,
    /// Native recovered `i` (convenience only).
    pub i: u64,
}

/// Build the full R1CS for one PRF symbol check on `shifted`, with the witness
/// assigned by the gadget's own computation. Returns the finalized system plus
/// the wire indices the gadget exposes.
pub fn build_power_residue_prf_symbol(shifted: Fp192) -> (Fp192R1cs, PrfSymbolWires) {
    let params = &*crate::primitives::prf::power_residue::DEFAULT_PARAMS;
    let mut builder = Fp192R1csBuilder::new();
    let shifted_var = builder.alloc_input(shifted);
    let out = power_residue_prf_symbol_circuit(&mut builder, params, &shifted_var);
    let wires = PrfSymbolWires {
        symbol_idx: out.symbol.idx,
        bit_idx: core::array::from_fn(|k| out.index_bits[k].idx),
        factor_idx: core::array::from_fn(|k| out.factors[k].idx),
        fold_idx: core::array::from_fn(|k| out.fold_acc[k].idx),
        index_idx: out.index.idx,
        i: out.i,
    };
    (builder.finalize(), wires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::griffin_p192::plum_griffin_permutation_raw;

    /// THE GATE.
    /// (1) build R1CS for one Griffin-Fp192 permutation as a function of input
    ///     wires; (2) witness assigned by the gadget's own computation;
    /// (3) every constraint satisfied by the correct witness; (4) the gadget's
    /// output wires equal the software `griffin_p192` permutation output.
    #[test]
    fn griffin_fp192_gadget_matches_software_and_is_satisfied() {
        let input: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
            core::array::from_fn(|i| Fp192::from_u64((i as u64) * 31 + 7));

        // Software reference output.
        let mut expected = input.clone();
        plum_griffin_permutation_raw(&mut expected);

        // Gadget R1CS + witness.
        let (r1cs, out_idx) = build_griffin_fp192_permutation(input.clone());

        // (3) every constraint satisfied.
        if let Err(bad) = r1cs.check_satisfied() {
            panic!("constraint #{bad} not satisfied by the gadget's own witness");
        }

        // (4) claimed output wires == software permutation output.
        for lane in 0..PLUM_GRIFFIN_STATE_WIDTH {
            assert_eq!(
                r1cs.assignment[out_idx[lane]], expected[lane],
                "output lane {lane} mismatch vs software griffin_p192",
            );
        }

        eprintln!(
            "Griffin-Fp192 permutation R1CS: {} constraints, {} variables",
            r1cs.num_constraints(),
            r1cs.num_variables,
        );
    }

    // -----------------------------------------------------------------------
    // Stage 3: t-th Power Residue PRF symbol-check gate.
    // -----------------------------------------------------------------------
    use crate::primitives::prf::power_residue::DEFAULT_PARAMS;

    /// THE STAGE-3 GATE.
    /// (1) build R1CS for one PRF symbol check; (2) witness assigned by the
    /// gadget's own computation; (3) every constraint satisfied by the correct
    /// witness; (4) the gadget's computed symbol field element equals the
    /// software PLUM PRF symbol `shifted^((p-1)/t)`, AND the recovered `i`
    /// equals `PowerResidueParams::eval(shifted)`.
    #[test]
    fn power_residue_prf_symbol_gadget_matches_software_and_is_satisfied() {
        let params = &*DEFAULT_PARAMS;
        // A few nonzero inputs (the PLUM-verify domain; o_responses != 0).
        for raw in [7u64, 0xdead_beef, 0x1234_5678_9abc_def0, 42, 999_983] {
            let shifted = Fp192::from_u64(raw);

            // Software reference: symbol field element + integer i.
            let software_symbol = shifted.t_power_residue_raw();
            let software_i = params.eval(&shifted);

            // Gadget R1CS + witness.
            let (r1cs, w) = build_power_residue_prf_symbol(shifted.clone());

            // (3) every constraint satisfied by the gadget's own witness.
            if let Err(bad) = r1cs.check_satisfied() {
                panic!(
                    "input {raw:#x}: constraint #{bad} not satisfied by the gadget's own witness"
                );
            }

            // (4a) computed symbol wire == software field exponentiation.
            assert_eq!(
                r1cs.assignment[w.symbol_idx], software_symbol,
                "input {raw:#x}: gadget symbol wire != software shifted^((p-1)/t)",
            );
            // (4b) recovered discrete log == software PRF eval.
            assert_eq!(
                w.i, software_i,
                "input {raw:#x}: gadget i != software PowerResidueParams::eval",
            );
            // (4c) the CONSTRAINED integer-index wire equals software i.
            assert_eq!(
                r1cs.assignment[w.index_idx], Fp192::from_u64(software_i),
                "input {raw:#x}: constrained index wire != software i",
            );

            eprintln!(
                "PRF symbol-check R1CS (input {raw:#x}): {} constraints, {} variables, i={}",
                r1cs.num_constraints(),
                r1cs.num_variables,
                w.i,
            );
        }
    }

    /// A wrong witness must be rejected for the PRF gadget (negative control,
    /// mirroring `corrupted_witness_is_rejected` for Griffin). Corrupt an
    /// interior squaring wire and confirm the satisfaction checker fails.
    #[test]
    fn prf_symbol_corrupted_witness_is_rejected() {
        let shifted = Fp192::from_u64(0xfeed_face);
        let (mut r1cs, w) = build_power_residue_prf_symbol(shifted);
        // Index 5 is an interior square-and-multiply wire (past the constant-1
        // slot at 0, the input at 1, the constant-one seed of pow at 2, and the
        // first couple of squarings) — flipping it must break the `x*x=out`
        // constraint that produced it.
        assert!(
            w.symbol_idx > 5,
            "expected the symbol chain to have > 5 wires; got symbol_idx={}",
            w.symbol_idx,
        );
        r1cs.assignment[5] = r1cs.assignment[5].clone() + Fp192::one();
        assert!(
            r1cs.check_satisfied().is_err(),
            "checker accepted a corrupted PRF witness",
        );
    }

    /// ADVERSARIAL AUDIT (engineer-agent, 2026-06-22). Three independent
    /// checks the existing gate does not cover:
    ///   (A) FIDELITY on >=4 fresh random inputs + edge inputs 1 and 0.
    ///   (B) EXPONENT is the FULL ~191-bit (p-1)/256, not 128-bit truncated:
    ///       direct bit-length + value assertion, AND a divergence input where
    ///       the truncated exponent would yield a DIFFERENT symbol.
    ///   (C) SOUNDNESS: corrupting the SYMBOL OUTPUT wire and corrupting an
    ///       interior power each break >=1 constraint.
    #[test]
    fn prf_gadget_adversarial_audit() {
        use num_bigint::BigUint;

        let params = &*DEFAULT_PARAMS;

        // ---- (B1) exponent provenance: full ~191-bit value -------------
        let p = Fp192::modulus();
        let independent = (&p - 1u32) / params.t; // recomputed here, not from the gadget
        assert_eq!(
            params.p_minus_1_over_t, independent,
            "params exponent != independently recomputed (p-1)/t",
        );
        let bits = params.p_minus_1_over_t.bits();
        eprintln!("(B1) (p-1)/256 bit length = {bits} (p bits = {})", p.bits());
        assert!(
            bits >= 188 && bits <= 192,
            "exponent bit length {bits} not in the ~191-bit window expected for a 199-bit prime / 256",
        );
        // A 128-bit truncation would lose the high bits: assert they exist.
        assert!(
            (&params.p_minus_1_over_t >> 128u32) != BigUint::from(0u32),
            "exponent has NO bits above 128 — a u128 path could not be distinguished",
        );

        // ---- (B2) divergence: truncated exponent gives a DIFFERENT symbol ----
        // Build the low-128-bit truncation of the real exponent and show the
        // gadget's symbol (full exponent) differs from base^(truncated) for a
        // concrete input. If they matched, the test could not catch truncation.
        let full = &params.p_minus_1_over_t;
        let mask128 = (BigUint::from(1u32) << 128u32) - 1u32;
        let truncated = full & &mask128;
        assert_ne!(*full, truncated, "masking changed nothing — high bits absent");
        let divergence_input = Fp192::from_u64(7);
        let full_symbol = divergence_input.pow_biguint(full);
        let trunc_symbol = divergence_input.pow_biguint(&truncated);
        assert_ne!(
            full_symbol, trunc_symbol,
            "full-exponent symbol == truncated-exponent symbol for input 7; \
             a truncation bug would be invisible on this input",
        );
        let (r1cs7, w7) = build_power_residue_prf_symbol(divergence_input.clone());
        let sym7_idx = w7.symbol_idx;
        assert_eq!(
            r1cs7.assignment[sym7_idx], full_symbol,
            "gadget symbol != full-exponent software symbol (gadget may be truncating)",
        );
        assert_ne!(
            r1cs7.assignment[sym7_idx], trunc_symbol,
            "gadget symbol == TRUNCATED-exponent symbol — gadget is using a 128-bit exponent",
        );
        eprintln!("(B2) full-symbol != truncated-symbol for input 7: divergence confirmed");

        // ---- (A) fidelity on fresh random inputs + edge inputs ---------
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([191u8; 32]);
        let mut tested = 0;
        let mut inputs: Vec<Fp192> = (0..6).map(|_| Fp192::rand_nonzero(&mut rng)).collect();
        inputs.push(Fp192::one()); // edge input 1
        for shifted in &inputs {
            let software_symbol = shifted.t_power_residue_raw();
            let software_i = params.eval(shifted);
            let (r1cs, w) = build_power_residue_prf_symbol(shifted.clone());
            assert!(
                r1cs.check_satisfied().is_ok(),
                "(A) constraints unsatisfied for a fresh input",
            );
            assert_eq!(
                r1cs.assignment[w.symbol_idx], software_symbol,
                "(A) gadget symbol != software t_power_residue_raw",
            );
            assert_eq!(w.i, software_i, "(A) gadget i != software eval");
            tested += 1;
        }
        assert!(tested >= 5, "expected >=5 fidelity inputs, got {tested}");
        eprintln!("(A) fidelity held on {tested} inputs (incl. edge input 1)");

        // edge input 0: documented out-of-domain -> the gadget must panic,
        // not silently mis-encode. Confirm it panics.
        let zero_panics = std::panic::catch_unwind(|| {
            build_power_residue_prf_symbol(Fp192::zero())
        })
        .is_err();
        assert!(zero_panics, "(A) gadget did NOT panic on edge input 0");
        eprintln!("(A) edge input 0 correctly panics (out-of-domain)");

        // ---- (C) soundness: corrupt the SYMBOL OUTPUT wire -------------
        {
            let (mut r1cs, w) =
                build_power_residue_prf_symbol(Fp192::from_u64(0xabc_123));
            assert!(r1cs.check_satisfied().is_ok(), "(C) baseline unsatisfied");
            r1cs.assignment[w.symbol_idx] = r1cs.assignment[w.symbol_idx].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "(C) checker ACCEPTED a corrupted SYMBOL OUTPUT wire — the \
                 symbol==omega^i binding is not enforced",
            );
        }
        // ---- (C) soundness: corrupt every interior power wire one-by-one ----
        {
            let (base_r1cs, w) =
                build_power_residue_prf_symbol(Fp192::from_u64(0xabc_123));
            let symbol_idx = w.symbol_idx;
            let n = base_r1cs.assignment.len();
            let mut all_caught = true;
            // wires 2..symbol_idx are interior pow squaring/multiply outputs.
            for wi in 2..symbol_idx {
                let mut r = base_r1cs.clone();
                r.assignment[wi] = r.assignment[wi].clone() + Fp192::one();
                if r.check_satisfied().is_ok() {
                    all_caught = false;
                    eprintln!("(C) corrupting interior wire {wi} was NOT caught");
                }
            }
            eprintln!(
                "(C) corrupted each interior wire in 2..{symbol_idx} (of {n} total); all caught = {all_caught}",
            );
            assert!(
                all_caught,
                "(C) at least one interior power wire is UNCONSTRAINED",
            );
        }
        eprintln!("ADVERSARIAL AUDIT PASSED");
    }

    /// STAGE-3 INDEX-BINDING GATE (engineer-agent, 2026-06-22).
    /// The defect being closed: PLUM's verifier consumes the INTEGER index
    /// `i = dlog_ω(symbol)` (`verify.rs:247`), not the field symbol. The fix
    /// allocates `i` as 8 boolean wires, recomputes `ω^i` in-circuit, and binds
    /// `symbol == ω^i`. This test confirms:
    ///   (1) the 8 bit wires are genuinely boolean-constrained (corrupting a
    ///       bit to a non-bit value is rejected);
    ///   (2) a prover who assigns the bits to ANY wrong `i != true dlog` makes
    ///       >=1 constraint fail (forged-index rejection);
    ///   (3) corrupting the recomposed integer-index wire is rejected;
    ///   (4) the index wire genuinely equals the software PRF integer output.
    #[test]
    fn prf_index_binding_is_constrained() {
        let params = &*DEFAULT_PARAMS;

        for raw in [7u64, 0xdead_beef, 0x1234_5678_9abc_def0, 42, 999_983] {
            let shifted = Fp192::from_u64(raw);
            let true_i = params.eval(&shifted);

            // Baseline: honest witness satisfies everything.
            let (base, w) = build_power_residue_prf_symbol(shifted.clone());
            assert!(
                base.check_satisfied().is_ok(),
                "input {raw:#x}: honest witness unsatisfied",
            );
            assert_eq!(
                base.assignment[w.index_idx],
                Fp192::from_u64(true_i),
                "input {raw:#x}: index wire != software i",
            );

            // (1) BOOLEAN ENFORCEMENT, isolated. Set bit b_k to the non-boolean
            //     value 2 AND co-mutate its select-factor f_k to the value the
            //     select_const linear constraint demands (f_k = 1 + b_k*(ω^(2^k)
            //     - 1)), so that the ONLY constraint left to catch the cheat is
            //     b*b=b. If b*b=b were absent, b_k=2 with a consistent factor
            //     would slip through; this asserts the boolean constraint is
            //     genuinely load-bearing, not redundant with select_const.
            for k in 0..8 {
                let mut r = base.clone();
                let two = Fp192::from_u64(2);
                let omega_pow_2k = params.omega.pow_u128(1u128 << k);
                // f_k = 1 + 2*(ω^(2^k) - 1)
                let consistent_factor =
                    Fp192::one() + two.clone() * (omega_pow_2k - Fp192::one());
                r.assignment[w.bit_idx[k]] = two;
                r.assignment[w.factor_idx[k]] = consistent_factor;
                // The fold product downstream is now stale, so the final
                // equality could also fail — but b*b=b is the first/intended
                // guard. We only require >=1 constraint to fire.
                let res = r.check_satisfied();
                assert!(
                    res.is_err(),
                    "input {raw:#x}: bit {k}=2 with consistent factor was ACCEPTED \
                     — b*b=b not enforced",
                );
                // Confirm the FIRST failing constraint is exactly b_k's b*b=b:
                // that constraint reads `b*b=b` over a single wire, so we check
                // the failing constraint involves only bit_idx[k].
                let bad = res.unwrap_err();
                let con = &r.constraints[bad];
                let is_bool_con = con.a.len() == 1
                    && con.b.len() == 1
                    && con.c.len() == 1
                    && con.a[0].0 == w.bit_idx[k]
                    && con.b[0].0 == w.bit_idx[k]
                    && con.c[0].0 == w.bit_idx[k];
                assert!(
                    is_bool_con,
                    "input {raw:#x}: bit {k}=2 was caught by constraint #{bad} \
                     which is NOT b_k's boolean constraint (b*b=b); the boolean \
                     guard may be missing",
                );
            }

            // (2) FORGED INDEX: assign the bits to every wrong j != true_i and
            //     confirm rejection. To make the forged witness internally
            //     consistent we also flip the recomposed index wire and the
            //     in-circuit ω^i fold — but those are recomputed by the gadget
            //     from the bits, so here we re-run the gadget logic by directly
            //     reassigning the bit wires AND propagating the omega^i product
            //     the honest prover would; the equality symbol==ω^j must then
            //     fail because ω^j != symbol for j != true_i (ω has order 256).
            //
            //     We test the strongest forgery: the prover keeps the true
            //     symbol (so its arithmetic core is honest) but lies about the
            //     index bits. Any consistent re-derivation of ω^j from the
            //     forged bits gives ω^j != symbol => equality fails. We model
            //     "consistent re-derivation" by rebuilding the whole system with
            //     forged bits via a helper.
            for j in 0u64..256 {
                if j == true_i {
                    continue;
                }
                // STRONGEST FORGERY: build a FULLY CONSISTENT witness for j.
                // Overwrite the 8 bit wires (still 0/1, boolean ok), recompute
                // every select-factor f_k, the 7 fold accumulators, and the
                // recomposed index wire — exactly as an honest prover would for
                // index j. The ONLY honest wire left is `symbol` (the true
                // residue). Because ω has order 256, ω^j != symbol for j != i,
                // so the SOLE constraint that can catch this is the final
                // equality `symbol == ω^j`. This directly exercises the
                // symbol-binding, not select_const's stale-factor guard.
                let mut r = base.clone();
                let one_v = Fp192::one();
                // bits + factors
                let mut fold_val: Option<Fp192> = None;
                let mut fold_k = 0usize;
                for k in 0..8 {
                    let bit = (j >> k) & 1 == 1;
                    r.assignment[w.bit_idx[k]] =
                        if bit { one_v.clone() } else { Fp192::zero() };
                    let omega_pow_2k = params.omega.pow_u128(1u128 << k);
                    let factor =
                        if bit { omega_pow_2k } else { one_v.clone() };
                    r.assignment[w.factor_idx[k]] = factor.clone();
                    fold_val = Some(match fold_val {
                        None => factor,
                        Some(acc) => {
                            let prod = acc * factor;
                            r.assignment[w.fold_idx[fold_k]] = prod.clone();
                            fold_k += 1;
                            prod
                        }
                    });
                }
                // recomposed index wire
                r.assignment[w.index_idx] = Fp192::from_u64(j);
                // Now the witness is internally consistent for j and ω^j; only
                // `symbol == ω^j` (j != true_i) must fail.
                assert!(
                    r.check_satisfied().is_err(),
                    "input {raw:#x}: FULLY-CONSISTENT forged index j={j} \
                     (true={true_i}) was ACCEPTED — symbol==ω^i binding broken",
                );
            }

            // (3) corrupt the recomposed integer-index wire alone.
            {
                let mut r = base.clone();
                r.assignment[w.index_idx] =
                    r.assignment[w.index_idx].clone() + Fp192::one();
                assert!(
                    r.check_satisfied().is_err(),
                    "input {raw:#x}: corrupted index wire ACCEPTED — recomposition \
                     constraint missing",
                );
            }
        }
        eprintln!("INDEX-BINDING GATE PASSED (bits boolean-constrained, forged i rejected)");
    }

    /// THE STAGE 4c-4-pi GATE: public-input / INSTANCE boundary.
    ///
    /// Build a tiny circuit with >= 1 public input and >= 1 private wire over a
    /// real relation, and assert the four required properties:
    ///   (1) the honest full assignment satisfies every constraint;
    ///   (2) `num_inputs` is correct and the public wires are exactly the
    ///       `[1, num_inputs]` prefix;
    ///   (3) the public-input (INSTANCE) vector reads back distinctly from the
    ///       private witness tail;
    ///   (4) backward compat: a builder with NO public input finalizes to
    ///       `num_inputs == 0` and an empty instance vector.
    #[test]
    fn public_input_boundary_gate() {
        // Relation:  pub_a * pub_b == priv_prod  (priv_prod is private witness).
        // Two public inputs fix the verifier-visible instance; the product wire
        // and the constant-1 seed of any helper are private.
        let mut b = Fp192R1csBuilder::new();
        let pub_a = b.alloc_public_input(Fp192::from_u64(6));
        let pub_b = b.alloc_public_input(Fp192::from_u64(7));
        // mul allocates a FRESH (private) product wire and constrains it.
        let prod = b.mul_pub(&pub_a, &pub_b);
        // Pin the public product to an independently allocated private witness
        // so there is a genuine private wire beyond the product itself.
        let priv_check = b.alloc_witness_pub(Fp192::from_u64(42));
        b.enforce_eq_pub(&prod, &priv_check);

        let prod_idx = prod.index();
        let priv_idx = priv_check.index();
        let r1cs = b.finalize();

        // (1) honest assignment satisfies all constraints.
        if let Err(bad) = r1cs.check_satisfied() {
            panic!("constraint #{bad} not satisfied by the honest assignment");
        }

        // (2) num_inputs correct, public wires are the [1, num_inputs] prefix.
        assert_eq!(r1cs.num_inputs, 2, "expected exactly 2 public inputs");
        assert_eq!(pub_a.index(), 1, "public input A must be at prefix index 1");
        assert_eq!(pub_b.index(), 2, "public input B must be at prefix index 2");
        assert!(
            prod_idx > r1cs.num_inputs && priv_idx > r1cs.num_inputs,
            "private wires (prod={prod_idx}, check={priv_idx}) must live beyond \
             the public prefix [1, {}]",
            r1cs.num_inputs,
        );

        // (3) instance vector reads back distinctly from the private witness.
        let instance = r1cs.public_inputs();
        assert_eq!(instance.len(), 2, "instance vector length == num_inputs");
        assert_eq!(instance[0], Fp192::from_u64(6));
        assert_eq!(instance[1], Fp192::from_u64(7));
        let witness = r1cs.private_witness();
        // The product (6*7=42) and the pinned check wire are both private.
        assert!(
            witness.iter().any(|w| *w == Fp192::from_u64(42)),
            "private witness must contain the product wire value 42",
        );
        // The public values must NOT leak into the private tail at the prefix
        // positions: instance and witness are disjoint slices of `assignment`.
        assert_eq!(
            instance.len() + witness.len() + 1, // +1 for the constant-1 slot
            r1cs.num_variables,
            "instance + witness + const-1 must partition the assignment",
        );

        // (4) BACKWARD COMPAT: a no-public-input builder is the legacy path.
        let legacy = build_griffin_fp192_permutation(core::array::from_fn(|i| {
            Fp192::from_u64((i as u64) * 5 + 3)
        }))
        .0;
        assert_eq!(
            legacy.num_inputs, 0,
            "legacy all-private gadget must report num_inputs == 0",
        );
        assert!(
            legacy.public_inputs().is_empty(),
            "legacy gadget instance vector must be empty",
        );
        assert!(legacy.check_satisfied().is_ok());

        eprintln!(
            "PUBLIC-INPUT BOUNDARY GATE PASSED: num_inputs={}, instance={:?}, \
             private_len={}, num_variables={}",
            r1cs.num_inputs,
            instance.len(),
            witness.len(),
            r1cs.num_variables,
        );
    }

    /// Allocating a public input AFTER a private wire must panic (the clean
    /// prefix invariant cannot be silently violated).
    #[test]
    #[should_panic(expected = "alloc_public_input must precede any private wire")]
    fn public_input_after_private_wire_panics() {
        let mut b = Fp192R1csBuilder::new();
        let _priv = b.alloc_input(Fp192::from_u64(1)); // private wire first
        let _bad = b.alloc_public_input(Fp192::from_u64(2)); // must panic
    }

    /// A wrong witness must be rejected (negative control — the satisfaction
    /// checker is not vacuously passing).
    #[test]
    fn corrupted_witness_is_rejected() {
        let input: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
            core::array::from_fn(|i| Fp192::from_u64((i as u64) * 13 + 1));
        let (mut r1cs, _out) = build_griffin_fp192_permutation(input);
        // Corrupt an interior witness wire (index 5 is past the inputs).
        r1cs.assignment[5] = r1cs.assignment[5].clone() + Fp192::one();
        assert!(
            r1cs.check_satisfied().is_err(),
            "checker accepted a corrupted witness",
        );
    }
}
