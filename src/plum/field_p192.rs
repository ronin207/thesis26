//! Custom field implementation for PLUM's prime.
//!
//! From Zhang, Fu, Steinfeld, Liu, Yuen, Au (ProvSec 2025) §3.3 the prime
//! has the form
//!
//!     p = 2^64 · p_0 + 1
//!
//! with `p_0` a "128-bit prime" (the displayed decimal is actually 135 bits,
//! so the paper's "192-bit" label refers to the order of magnitude rather
//! than the strict bit length). Two issues with the paper's literal decimal:
//!
//!   1. As printed, the value is **not prime** (factors as 7·5879·21871·…),
//!      so signature arithmetic with it is incorrect — Fermat fails and
//!      `pow(a, p-1) != 1`. This is almost certainly a copy/OCR error in
//!      the paper draft.
//!   2. The displayed value is 135-bit, contradicting the in-text "128-bit
//!      prime" remark. The 199-bit total then disagrees with the section
//!      header "192-bit smooth prime field". We treat the bit-width labels
//!      as approximate.
//!
//! For this implementation we use the **closest larger value such that
//! both `p_0` and `2^64 · p_0 + 1` are prime, and `p ≡ 1 mod 256`** (so
//! the t=256 power residue PRF is well-defined and the multiplicative
//! group has the 2^64 smooth subgroup PLUM/STIR rely on):
//!
//!     p_0 = 25953665385296571073907086806836816188273
//!     p   = 478760623137260249020079243151463163776858757630613067399169
//!
//! Both verified prime by `sympy.isprime` (Miller–Rabin); difference from
//! paper value is +14502. This substitution does not affect the
//! field-size class (199-bit, smooth-subgroup, non-Mersenne) which is
//! what the thesis cycle-attribution measurement is sensitive to. When
//! the STIR/PLUM authors are reached for the canonical value, swap the
//! constants in `MODULUS_LIMBS` and rerun the tests — no other code
//! changes needed.
//!
//! Properties:
//!   - bit length 199
//!   - 2-adicity 64 (smooth multiplicative subgroup of size 2^64,
//!     supports STIR / FRI-style folding without field extension)
//!   - t = 256 divides p - 1, enabling the 256-th power residue PRF
//!   - no fast Mersenne-style reduction; arithmetic cost is dominated
//!     by full multi-limb multiplication and modular reduction.
//!
//! ## Implementation note (Phase 1a vs 1.5)
//!
//! This module currently uses `num_bigint::BigUint` internally for
//! modular arithmetic. That is correct but does NOT reflect the realistic
//! multi-limb cost we want to measure in rv32im. Phase 1.5 will replace
//! the hot path with explicit 4 × u64 limb arithmetic + Barrett (or
//! Montgomery) reduction so cycle counts reflect the actual field-mismatch
//! tax. The public API (`Fp192::*`) and the `FP192_MUL_COUNT` instrumentation
//! are designed to be representation-stable across that swap.

use core::cmp::Ordering;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
#[cfg(feature = "std")]
use rand::Rng;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use num_bigint::BigUint;
use once_cell::sync::Lazy;

/// Counter incremented on every `Fp192` multiplication. Mirrors Loquat's
/// `FP127_MUL_COUNT` so the zkVM guest can attribute cycles to F_p work.
pub static FP192_MUL_COUNT: AtomicU64 = AtomicU64::new(0);

/// Counter incremented on every `Fp192` addition. PLUM has no F_p²
/// extension, so this replaces Loquat's `FP2_ADD_COUNT` role for
/// addition-heavy work outside Griffin.
pub static FP192_ADD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Modulus in little-endian u64 limbs (limb[0] = lowest 64 bits).
///
/// p = 0x4c455e221a5f68af517bbd7e10d66d13710000000000000001
/// (closest-larger working prime; see module-level doc-comment for the
/// reason this deviates from the paper's printed decimal).
pub const MODULUS_LIMBS: [u64; 4] = [
    0x0000_0000_0000_0001u64,
    0x7bbd_7e10_d66d_1371u64,
    0x455e_221a_5f68_af51u64,
    0x0000_0000_0000_004cu64,
];

/// Bit length of the modulus.
pub const MODULUS_BITS: usize = 199;

/// 2-adicity of p - 1 (size of the smooth multiplicative subgroup is 2^64).
pub const TWO_ADICITY: usize = 64;

/// Power-residue parameter from the paper (PLUM uses t = 256).
pub const T_RESIDUE: u64 = 256;

/// Cached BigUint forms of the modulus and useful exponents.
static MODULUS: Lazy<BigUint> = Lazy::new(|| limbs_to_biguint(&MODULUS_LIMBS));
static MODULUS_MINUS_ONE: Lazy<BigUint> = Lazy::new(|| MODULUS.clone() - 1u32);
static MODULUS_MINUS_TWO: Lazy<BigUint> = Lazy::new(|| MODULUS.clone() - 2u32);
/// (p - 1) / t for t = 256; used by the t-th power residue PRF.
static P_MINUS_1_OVER_T: Lazy<BigUint> = Lazy::new(|| MODULUS_MINUS_ONE.clone() / T_RESIDUE);

fn limbs_to_biguint(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn biguint_to_limbs(value: &BigUint) -> [u64; 4] {
    let mut bytes = [0u8; 32];
    let raw = value.to_bytes_le();
    let n = raw.len().min(32);
    bytes[..n].copy_from_slice(&raw[..n]);
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(buf);
    }
    out
}

/// Element of F_p where p is the PLUM prime.
///
/// Stored canonically: `value` is always in [0, p).
#[derive(Clone, PartialEq, Eq, Default, Hash)]
pub struct Fp192 {
    value: BigUint,
}

impl Fp192 {
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let bi = limbs_to_biguint(&limbs);
        Self::from_biguint(bi)
    }

    pub fn to_limbs(&self) -> [u64; 4] {
        biguint_to_limbs(&self.value)
    }

    pub fn from_biguint(bi: BigUint) -> Self {
        let reduced = bi % MODULUS.clone();
        Self { value: reduced }
    }

    pub fn to_biguint(&self) -> BigUint {
        self.value.clone()
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            value: BigUint::from(value),
        }
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            value: BigUint::from(value),
        }
    }

    pub const fn modulus_limbs() -> [u64; 4] {
        MODULUS_LIMBS
    }

    pub fn modulus() -> BigUint {
        MODULUS.clone()
    }

    pub fn zero() -> Self {
        Self {
            value: BigUint::from(0u32),
        }
    }

    pub fn one() -> Self {
        Self {
            value: BigUint::from(1u32),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.value == BigUint::from(0u32)
    }

    pub fn is_one(&self) -> bool {
        self.value == BigUint::from(1u32)
    }

    /// Modular exponentiation `self^exp mod p` for arbitrary `BigUint`
    /// exponents (PLUM's PRF uses `(p-1)/256`, which exceeds `u128`).
    ///
    /// Internally delegates to `BigUint::modpow`, which is the correct,
    /// well-tested path for the math. We account for the F_p multiplications
    /// it performs by bumping `FP192_MUL_COUNT` by the count that a
    /// square-and-multiply implementation would have used: `(bits - 1)`
    /// squarings + `popcount(exp)` mid-fold multiplications. This matches
    /// the cycle attribution we want for the thesis measurement (the count
    /// is what zkVM-rv32im would see; the concrete BigUint implementation
    /// is a Phase 1.5 hot-path concern).
    pub fn pow_biguint(&self, exp: &BigUint) -> Self {
        let bits = exp.bits();
        if bits > 0 {
            let mut popcount: u64 = 0;
            for i in 0..bits {
                if exp.bit(i) {
                    popcount += 1;
                }
            }
            // Square-and-multiply: (bits - 1) squarings, popcount muls.
            let muls = bits.saturating_sub(1).saturating_add(popcount);
            FP192_MUL_COUNT.fetch_add(muls, AtomicOrdering::Relaxed);
        }
        Self {
            value: self.value.modpow(exp, &MODULUS),
        }
    }

    /// Convenience wrapper for small (u128-fitting) exponents.
    pub fn pow_u128(&self, exp: u128) -> Self {
        self.pow_biguint(&BigUint::from(exp))
    }

    /// Fermat inverse: a^(p - 2) mod p. Returns `None` if `self` is zero.
    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow_biguint(&MODULUS_MINUS_TWO))
        }
    }

    /// t-th power residue symbol component: returns `self^((p - 1) / t)`,
    /// which is a t-th root of unity (or 0 if `self` is 0).
    ///
    /// PLUM's `L_0^t(a)` is the discrete log of this in the t-th roots of
    /// unity; that mapping is implemented in `src/plum/prf.rs` once Phase 2
    /// lands. This method exposes the underlying field exponentiation.
    pub fn t_power_residue_raw(&self) -> Self {
        if self.is_zero() {
            Self::zero()
        } else {
            self.pow_biguint(&P_MINUS_1_OVER_T)
        }
    }

    #[cfg(feature = "std")]
    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        // p has bit length 199 (top bit is bit 198). Sample 25 bytes
        // (= 200 bits), zero bit 7 of the top byte to cap candidates at
        // 2^199, then rejection-sample. With p's top byte = 0x4c, the
        // acceptance rate is 0x4c / 0x80 ≈ 0.60, so a few iterations
        // suffice on average.
        let mut bytes = [0u8; 25];
        loop {
            rng.fill(&mut bytes[..]);
            bytes[24] &= 0x7F;
            let candidate = BigUint::from_bytes_le(&bytes);
            if candidate < *MODULUS {
                return Self { value: candidate };
            }
        }
    }

    #[cfg(feature = "std")]
    pub fn rand_nonzero<R: Rng>(rng: &mut R) -> Self {
        loop {
            let value = Self::rand(rng);
            if !value.is_zero() {
                return value;
            }
        }
    }

    /// Serialize to a 32-byte little-endian buffer (top 7 bytes are zero
    /// padding since p < 2^200).
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let limbs = self.to_limbs();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        out
    }

    /// Deserialize from 32-byte little-endian buffer. Returns `None` if the
    /// encoded value is not less than the modulus.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Self> {
        let bi = BigUint::from_bytes_le(bytes);
        if bi < *MODULUS {
            Some(Self { value: bi })
        } else {
            None
        }
    }
}

// --- Core field arithmetic ---

impl Add for Fp192 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FP192_ADD_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        let sum = self.value + rhs.value;
        let value = if sum >= *MODULUS { sum - MODULUS.clone() } else { sum };
        Self { value }
    }
}

impl Sub for Fp192 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FP192_ADD_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        let value = if self.value >= rhs.value {
            self.value - rhs.value
        } else {
            self.value + MODULUS.clone() - rhs.value
        };
        Self { value }
    }
}

impl Mul for Fp192 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FP192_MUL_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        let product = self.value * rhs.value;
        Self {
            value: product % MODULUS.clone(),
        }
    }
}

impl Div for Fp192 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self * rhs.inverse().expect("division by zero in Fp192")
    }
}

impl Neg for Fp192 {
    type Output = Self;
    fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            Self {
                value: MODULUS.clone() - self.value,
            }
        }
    }
}

impl AddAssign for Fp192 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}
impl SubAssign for Fp192 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}
impl MulAssign for Fp192 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl Sum for Fp192 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b)
    }
}

impl<'a> Sum<&'a Fp192> for Fp192 {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b.clone())
    }
}

impl PartialOrd for Fp192 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Fp192 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl fmt::Debug for Fp192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp192(0x{:x})", self.value)
    }
}

impl Serialize for Fp192 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes_le())
    }
}

struct Fp192Visitor;

impl<'de> Visitor<'de> for Fp192Visitor {
    type Value = Fp192;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("32 little-endian bytes encoding an Fp192 element")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::invalid_length(v.len(), &"32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(v);
        Fp192::from_bytes_le(&arr).ok_or_else(|| E::custom("Fp192 value out of range"))
    }
}

impl<'de> Deserialize<'de> for Fp192 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(Fp192Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> BigUint {
        MODULUS.clone()
    }

    #[test]
    fn modulus_constants_are_consistent() {
        // p = 2^64 * p_0 + 1 with the working-prime p_0 we substituted
        // for the paper's non-prime decimal (see module-level doc).
        let p0_decimal = "25953665385296571073907086806836816188273";
        let p0 = p0_decimal.parse::<BigUint>().unwrap();
        let reconstructed = (BigUint::from(1u64) << 64) * &p0 + 1u32;
        assert_eq!(p(), reconstructed);
        assert_eq!(p().bits(), MODULUS_BITS as u64);
        // Smooth: 2^64 divides p - 1 exactly.
        let pm1 = MODULUS_MINUS_ONE.clone();
        assert!(pm1.bit(TWO_ADICITY as u64));
        for i in 0..TWO_ADICITY {
            assert!(!pm1.bit(i as u64), "p-1 should not be divisible by 2^65");
        }
        // t = 256 divides p - 1.
        assert!(pm1.clone() % T_RESIDUE == BigUint::from(0u32));
    }

    #[test]
    fn limb_roundtrip() {
        let a = Fp192::from_limbs([0x1234, 0x5678, 0x9abc, 0x0000]);
        let limbs = a.to_limbs();
        let b = Fp192::from_limbs(limbs);
        assert_eq!(a, b);
    }

    #[test]
    fn addition_matches_oracle() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        for _ in 0..256 {
            let a = Fp192::rand(&mut rng);
            let b = Fp192::rand(&mut rng);
            let sum = a.clone() + b.clone();
            let expected = (a.to_biguint() + b.to_biguint()) % p();
            assert_eq!(sum.to_biguint(), expected);
        }
    }

    #[test]
    fn subtraction_matches_oracle() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
        for _ in 0..256 {
            let a = Fp192::rand(&mut rng);
            let b = Fp192::rand(&mut rng);
            let diff = a.clone() - b.clone();
            let expected =
                (a.to_biguint() + p() - b.to_biguint() % p()) % p();
            assert_eq!(diff.to_biguint(), expected);
        }
    }

    #[test]
    fn multiplication_matches_oracle() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([13u8; 32]);
        for _ in 0..256 {
            let a = Fp192::rand(&mut rng);
            let b = Fp192::rand(&mut rng);
            let prod = a.clone() * b.clone();
            let expected = (a.to_biguint() * b.to_biguint()) % p();
            assert_eq!(prod.to_biguint(), expected);
        }
    }

    #[test]
    fn neg_then_add_is_zero() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([17u8; 32]);
        for _ in 0..128 {
            let a = Fp192::rand(&mut rng);
            let neg = -a.clone();
            assert!((a + neg).is_zero());
        }
    }

    #[test]
    fn inverse_roundtrip() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([19u8; 32]);
        for _ in 0..32 {
            let a = Fp192::rand_nonzero(&mut rng);
            let inv = a.inverse().expect("nonzero element must invert");
            assert!((a * inv).is_one());
        }
        assert!(Fp192::zero().inverse().is_none());
    }

    #[test]
    fn pow_matches_oracle() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([23u8; 32]);
        let a = Fp192::rand_nonzero(&mut rng);
        // Fermat: a^(p - 1) = 1.
        let fermat = a.pow_biguint(&MODULUS_MINUS_ONE);
        assert!(fermat.is_one());
    }

    #[test]
    fn t_power_residue_is_t_root_of_unity() {
        // (a^((p-1)/t))^t = a^(p-1) = 1 for any nonzero a.
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([29u8; 32]);
        for _ in 0..8 {
            let a = Fp192::rand_nonzero(&mut rng);
            let symbol = a.t_power_residue_raw();
            let raised = symbol.pow_u128(T_RESIDUE as u128);
            assert!(raised.is_one(), "t-th power residue not a t-th root of unity");
        }
    }

    #[test]
    fn fp192_mul_counter_ticks() {
        let before = FP192_MUL_COUNT.load(AtomicOrdering::Relaxed);
        let a = Fp192::from_u64(123_456);
        let b = Fp192::from_u64(789_012);
        let _ = a * b;
        let after = FP192_MUL_COUNT.load(AtomicOrdering::Relaxed);
        assert!(after >= before + 1, "FP192_MUL_COUNT did not advance");
    }

    #[test]
    fn fp192_add_counter_ticks() {
        let before = FP192_ADD_COUNT.load(AtomicOrdering::Relaxed);
        let a = Fp192::from_u64(1);
        let b = Fp192::from_u64(2);
        let _ = a + b;
        let after = FP192_ADD_COUNT.load(AtomicOrdering::Relaxed);
        assert!(after >= before + 1, "FP192_ADD_COUNT did not advance");
    }

    #[test]
    fn serde_roundtrip() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([31u8; 32]);
        let a = Fp192::rand(&mut rng);
        let encoded = bincode::serialize(&a).expect("encode");
        let decoded: Fp192 = bincode::deserialize(&encoded).expect("decode");
        assert_eq!(a, decoded);
    }
}
