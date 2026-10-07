//! ML-KEM (FIPS 203), the module-lattice key encapsulation
//! mechanism standardised from Kyber, in its three parameter sets.
//!
//! A key pair is a matrix equation over polynomials: the public key
//! is `t = A s + e` with `A` expanded from a public seed and `s`, `e`
//! small and secret; a ciphertext encrypts a random message under
//! it, and the shared secret is derived from that message and the
//! public key. Recovering `s` from `t` and `A` is the module
//! learning-with-errors problem, which no known quantum algorithm
//! solves. Each parameter set is a module of its own, [`ml_kem_512`],
//! [`ml_kem_768`] and [`ml_kem_1024`], with the same two key types
//! and the same calls; 768 is the set most deployments choose.
//!
//! The construction is Fujisaki-Okamoto with implicit rejection:
//! decapsulation re-encrypts the recovered message and, when the
//! result is not the ciphertext it was given, returns a secret
//! derived from the ciphertext and a hidden value instead of an
//! error, so a forged ciphertext yields a random key and no signal.
//! [`decapsulate`](ml_kem_768::PrivateKey::decapsulate) therefore
//! never fails on a well-formed ciphertext; that is the design, not
//! an omission.
//!
//! A private key is 64 bytes of seed, `d || z`, from which FIPS 203
//! derives everything else; the expanded form of 1632 to 3168 bytes
//! is what the standard's algorithms consume. Both are read and
//! written here, the seed being the form to store.
//!
//! ```
//! use scytale::kem::ml_kem::ml_kem_768::{PrivateKey, PublicKey};
//! use scytale::random::CtrDrbg;
//!
//! # fn main() -> Result<(), scytale::Error> {
//! let mut rng = CtrDrbg::from_system()?;
//! let key = PrivateKey::generate(&mut rng)?;
//!
//! // The sender has only the public key, and makes a ciphertext
//! // and a secret from it.
//! let public = PublicKey::try_new(&key.public_key().bytes())?;
//! let (ciphertext, secret) = public.encapsulate(&mut rng)?;
//!
//! // The key holder recovers the same secret from the ciphertext.
//! assert_eq!(key.decapsulate(&ciphertext), secret);
//! # Ok(())
//! # }
//! ```
//!
//! # Constant time
//!
//! Every coefficient operation is branch-free arithmetic on values
//! below the modulus, with reductions by multiply-and-shift rather
//! than division; the one comparison decapsulation makes, of the
//! ciphertext against its re-encryption, reads every byte and
//! chooses the result by a mask. Rejection sampling of the public
//! matrix `A` varies with the public seed alone.

use zeroize::Zeroize;

use crate::constant_time;
use crate::hash::sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use crate::hash::{Hash, Xof, XofReader};

/// The modulus.
const Q: u32 = 3329;

/// Coefficients in a polynomial.
const N: usize = 256;

/// The length of a seed, `d || z`.
const SEED: usize = 64;

/// The length of a shared secret.
const SECRET: usize = 32;

/// What a parameter set fixes beyond the module rank `K`: the noise
/// widths and the ciphertext compression.
struct Params {
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
}

const PARAMS_512: Params = Params {
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

const PARAMS_768: Params = Params {
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

const PARAMS_1024: Params = Params {
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// The length of an encapsulation key for rank `K`.
const fn public_len(k: usize) -> usize {
    384 * k + 32
}

/// The length of an expanded decapsulation key for rank `K`.
const fn private_len(k: usize) -> usize {
    768 * k + 96
}

/// The length of a ciphertext.
const fn ciphertext_len(k: usize, p: &Params) -> usize {
    32 * (p.du * k + p.dv)
}

// The ring: polynomials modulo x^256 + 1 over the integers modulo
// q, held in the number-theoretic transform domain for products.

/// The seven-bit reversal FIPS 203 orders its roots of unity by.
const fn bitrev7(i: usize) -> usize {
    let mut out = 0;
    let mut bit = 0;
    while bit < 7 {
        out |= ((i >> bit) & 1) << (6 - bit);
        bit += 1;
    }
    out
}

/// `17^e mod q`; 17 is the root of unity the transform is built on.
const fn zeta_pow(mut e: usize) -> u16 {
    let mut result = 1u32;
    let mut base = 17u32;
    while e > 0 {
        if e & 1 == 1 {
            result = result * base % Q;
        }
        base = base * base % Q;
        e >>= 1;
    }
    result as u16
}

/// The roots the transform's butterflies use, in the order it uses
/// them: `17^bitrev7(i)`.
const ZETAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = zeta_pow(bitrev7(i));
        i += 1;
    }
    table
};

/// The roots the pairwise products use: `17^(2 bitrev7(i) + 1)`.
const GAMMAS: [u16; 128] = {
    let mut table = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = zeta_pow(2 * bitrev7(i) + 1);
        i += 1;
    }
    table
};

// The transforms and the products run in signed 16-bit Montgomery
// arithmetic, with reductions left until the words would overflow:
// every step is then a 16-bit multiply and its high half, which the
// compiler lays across vector registers, where the 64-bit Barrett
// multiply below cannot be. Results are brought back to [0, q) on the
// way out, so the rest of the code sees only canonical coefficients.

/// `q^-1 mod 2^16`, as a signed word.
const QINV: i16 = -3327;

/// `x 2^16 mod q`, centred on zero, which keeps Montgomery products
/// of it small.
const fn to_montgomery(x: u16) -> i16 {
    let r = (x as u32 * 65536 % Q) as i32;
    (if r > (Q as i32) / 2 { r - Q as i32 } else { r }) as i16
}

/// The transform's roots, in Montgomery form.
const ZETAS_MONT: [i16; 128] = {
    let mut table = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = to_montgomery(ZETAS[i]);
        i += 1;
    }
    table
};

/// The pairwise products' roots, in Montgomery form.
const GAMMAS_MONT: [i16; 128] = {
    let mut table = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        table[i] = to_montgomery(GAMMAS[i]);
        i += 1;
    }
    table
};

/// `2^32 mod q`: a Montgomery product with it multiplies by `2^16`,
/// undoing the division one product leaves behind.
const R2: i16 = ((1u64 << 32) % Q as u64) as i16;

/// `128^-1 2^16 mod q`: a Montgomery product with it divides by 128.
const INV128_MONT: i16 = to_montgomery(3303);

/// The high half of a signed 16-bit product.
#[inline(always)]
fn mulhi(a: i16, b: i16) -> i16 {
    ((i32::from(a) * i32::from(b)) >> 16) as i16
}

/// `a b 2^-16 mod q`, in `(-q, q)` for `|a b| < q 2^15`.
///
/// Written in 16-bit halves: `a b - t q` is divisible by `2^16`
/// because `t` is chosen so its low half is `a b`'s, so the quotient
/// is the difference of the two high halves and no borrow crosses
/// between them. Those are the low and high multiplies vector
/// registers do sixteen bits at a time.
#[inline(always)]
fn fqmul(a: i16, b: i16) -> i16 {
    let t = a.wrapping_mul(b).wrapping_mul(QINV);
    mulhi(a, b) - mulhi(t, Q as i16)
}

/// `a mod q`, centred: in `[-(q-1)/2, (q-1)/2]` for any word.
///
/// The quotient is `(a V + 2^25) >> 26`, taken as the high half of
/// `a V` and then the remaining ten bits, which is the same number and
/// stays in sixteen bits throughout.
#[inline(always)]
fn barrett(a: i16) -> i16 {
    const V: i16 = (((1 << 26) + Q / 2) / Q) as i16;
    let t = (mulhi(a, V) + (1 << 9)) >> 10;
    a.wrapping_sub(t.wrapping_mul(Q as i16))
}

/// `a` in `(-q, q)` moved to `[0, q)`, by a masked addition.
#[inline(always)]
fn canonical(a: i16) -> u16 {
    (a + ((a >> 15) & Q as i16)) as u16
}

/// `a mod q` for `a` below `2q`, by one masked subtraction.
fn csub(a: u32) -> u16 {
    let r = a as i32 - Q as i32;
    (r + ((r >> 31) & Q as i32)) as u16
}

/// `a mod q` for any `a` below 2^26, by Barrett reduction: the
/// quotient estimate is off by at most one, which the final
/// subtraction absorbs.
fn reduce(a: u32) -> u16 {
    let quotient = ((u64::from(a) * 20158) >> 26) as u32;
    csub(a - quotient * Q)
}

fn add(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + u32::from(b))
}

fn sub(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + Q - u32::from(b))
}

/// The product by Barrett reduction, which the tests check the
/// Montgomery arithmetic against.
#[cfg(test)]
fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a) * u32::from(b))
}

/// A polynomial, its coefficients in `[0, q)`, in whichever domain
/// its use says.
#[derive(Clone, Copy)]
struct Poly([u16; N]);

impl Poly {
    const ZERO: Poly = Poly([0; N]);

    /// The transform, algorithm 9.
    ///
    /// Each layer adds at most `q` to a coefficient's magnitude, so
    /// from `[0, q)` seven layers stay below `8q`, inside a word; one
    /// reduction at the end is enough.
    fn ntt(&mut self) {
        let mut f = self.0.map(|c| c as i16);
        let mut k = 1;
        let mut len = 128;
        while len >= 2 {
            for block in f.chunks_exact_mut(2 * len) {
                let zeta = ZETAS_MONT[k];
                k += 1;
                let (low, high) = block.split_at_mut(len);
                for (a, b) in low.iter_mut().zip(high.iter_mut()) {
                    let t = fqmul(zeta, *b);
                    *b = *a - t;
                    *a += t;
                }
            }
            len /= 2;
        }
        for (c, &x) in self.0.iter_mut().zip(&f) {
            *c = canonical(barrett(x));
        }
    }

    /// The inverse transform, algorithm 10.
    ///
    /// The sums are reduced as they are made, which keeps them in a
    /// word; the differences go straight into a Montgomery product.
    fn inverse_ntt(&mut self) {
        let mut f = self.0.map(|c| c as i16);
        let mut k = 127;
        let mut len = 2;
        while len <= 128 {
            for block in f.chunks_exact_mut(2 * len) {
                let zeta = ZETAS_MONT[k];
                k -= 1;
                let (low, high) = block.split_at_mut(len);
                for (a, b) in low.iter_mut().zip(high.iter_mut()) {
                    let t = *a;
                    *a = barrett(t + *b);
                    *b = fqmul(zeta, *b - t);
                }
            }
            len *= 2;
        }
        // Divided by 128, which the butterflies left multiplied in.
        for (c, &x) in self.0.iter_mut().zip(&f) {
            *c = canonical(fqmul(x, INV128_MONT));
        }
    }

    /// The product in the transform domain, algorithm 11: pairs of
    /// coefficients multiplied modulo `x^2 - gamma`.
    ///
    /// Each Montgomery product divides by `2^16`, the same once in
    /// every term, and one more product by `2^32 mod q` puts it back.
    fn mul_ntt(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        let pairs = out
            .0
            .chunks_exact_mut(2)
            .zip(self.0.chunks_exact(2))
            .zip(other.0.chunks_exact(2));
        for (((c, a), b), gamma) in pairs.zip(GAMMAS_MONT) {
            let (a0, a1) = (a[0] as i16, a[1] as i16);
            let (b0, b1) = (b[0] as i16, b[1] as i16);
            let c0 = fqmul(fqmul(a1, b1), gamma) + fqmul(a0, b0);
            let c1 = fqmul(a0, b1) + fqmul(a1, b0);
            c[0] = canonical(fqmul(c0, R2));
            c[1] = canonical(fqmul(c1, R2));
        }
        out
    }

    fn add_assign(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a = add(*a, *b);
        }
    }

    fn sub_assign(&mut self, other: &Poly) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a = sub(*a, *b);
        }
    }

    /// Writes the coefficients as `d`-bit values, algorithm 5, into
    /// `32 d` bytes.
    fn encode(&self, d: usize, out: &mut [u8]) {
        debug_assert_eq!(out.len(), 32 * d);
        let mut acc = 0u64;
        let mut bits = 0;
        let mut pos = 0;
        for &c in &self.0 {
            acc |= u64::from(c) << bits;
            bits += d;
            while bits >= 8 {
                out[pos] = acc as u8;
                pos += 1;
                acc >>= 8;
                bits -= 8;
            }
        }
    }

    /// Reads `d`-bit coefficients, algorithm 6; at `d = 12` they are
    /// reduced modulo `q`, as the standard says, which is what makes
    /// the round trip check on a public key meaningful.
    fn decode(d: usize, bytes: &[u8]) -> Poly {
        debug_assert_eq!(bytes.len(), 32 * d);
        let mut out = Poly::ZERO;
        let mask = (1u64 << d) - 1;
        let mut acc = 0u64;
        let mut bits = 0;
        let mut pos = 0;
        for c in out.0.iter_mut() {
            while bits < d {
                acc |= u64::from(bytes[pos]) << bits;
                pos += 1;
                bits += 8;
            }
            let value = (acc & mask) as u32;
            acc >>= d;
            bits -= d;
            *c = if d == 12 { reduce(value) } else { value as u16 };
        }
        out
    }

    /// `Compress_d`, rounding `x q^-1 2^d`; the division is by a
    /// constant and compiles to a multiply.
    fn compress(&self, d: usize) -> Poly {
        let mut out = *self;
        for c in out.0.iter_mut() {
            let scaled = (u32::from(*c) << d) + Q / 2;
            *c = ((scaled / Q) & ((1 << d) - 1)) as u16;
        }
        out
    }

    /// `Decompress_d`, rounding `y 2^-d q`.
    fn decompress(&self, d: usize) -> Poly {
        let mut out = *self;
        for c in out.0.iter_mut() {
            *c = ((u32::from(*c) * Q + (1 << (d - 1))) >> d) as u16;
        }
        out
    }

    /// `SampleNTT`, algorithm 7: the entry of `A` at `row`, `col`,
    /// by rejection sampling from SHAKE-128 over the seed and the
    /// two indices, column first as the standard has it.
    fn sample_ntt(rho: &[u8; 32], row: u8, col: u8) -> Poly {
        let mut xof = Shake128::new();
        xof.update(rho);
        xof.update(&[col, row]);
        let mut reader = xof.finalize_xof();
        let mut out = Poly::ZERO;
        let mut filled = 0;
        // Three bytes give two twelve-bit candidates; a block of the
        // sponge's rate at a time.
        let mut buf = [0u8; 168];
        while filled < N {
            reader.squeeze(&mut buf);
            for chunk in buf.chunks_exact(3) {
                let d1 =
                    u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0f) << 8);
                let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);
                for d in [d1, d2] {
                    if filled < N && u32::from(d) < Q {
                        out.0[filled] = d;
                        filled += 1;
                    }
                }
            }
        }
        out
    }

    /// `SamplePolyCBD_eta`, algorithm 8, over `64 eta` bytes of PRF
    /// output: each coefficient a difference of two `eta`-bit sums.
    ///
    /// The bits are summed a word at a time rather than one by one:
    /// adjacent bits added pairwise (or in threes) under a mask give
    /// every coefficient's two sums side by side in one word, which
    /// shifts then take apart. The bits are the standard's, least
    /// significant first within each byte.
    fn sample_cbd(eta: usize, bytes: &[u8]) -> Poly {
        debug_assert_eq!(bytes.len(), 64 * eta);
        let mut out = Poly::ZERO;
        if eta == 2 {
            // Four bytes, eight coefficients of two two-bit sums.
            let words = bytes.chunks_exact(4);
            for (coefficients, word) in out.0.chunks_exact_mut(8).zip(words) {
                let t =
                    u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
                for (j, c) in coefficients.iter_mut().enumerate() {
                    let x = ((d >> (4 * j)) & 3) as u16;
                    let y = ((d >> (4 * j + 2)) & 3) as u16;
                    *c = sub(x, y);
                }
            }
        } else {
            debug_assert_eq!(eta, 3);
            // Three bytes, four coefficients of two three-bit sums.
            let words = bytes.chunks_exact(3);
            for (coefficients, word) in out.0.chunks_exact_mut(4).zip(words) {
                let t = u32::from_le_bytes([word[0], word[1], word[2], 0]);
                let d = (t & 0x0024_9249)
                    + ((t >> 1) & 0x0024_9249)
                    + ((t >> 2) & 0x0024_9249);
                for (j, c) in coefficients.iter_mut().enumerate() {
                    let x = ((d >> (6 * j)) & 7) as u16;
                    let y = ((d >> (6 * j + 3)) & 7) as u16;
                    *c = sub(x, y);
                }
            }
        }
        out
    }

    /// A polynomial of small coefficients from the PRF of `seed` and
    /// the counter `n`, `PRF_eta` feeding `SamplePolyCBD_eta`.
    fn sample_noise(eta: usize, seed: &[u8; 32], n: u8) -> Poly {
        let mut xof = Shake256::new();
        xof.update(seed);
        xof.update(&[n]);
        let mut bytes = [0u8; 64 * 3];
        xof.finalize_xof().squeeze(&mut bytes[..64 * eta]);
        let out = Poly::sample_cbd(eta, &bytes[..64 * eta]);
        bytes.zeroize();
        out
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// The scheme, over an expanded key of rank K.

/// `G`, SHA3-512 split in two.
fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut hash = Sha3_512::new();
    for part in parts {
        hash.update(part);
    }
    let mut digest = hash.finalize();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    b.copy_from_slice(&digest[32..]);
    // In decapsulation the first half is the shared secret itself.
    digest.zeroize();
    (a, b)
}

/// `H`, SHA3-256.
fn h(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data)
}

/// `J`, 32 bytes of SHAKE-256, for the implicit rejection secret.
fn j(z: &[u8], c: &[u8]) -> [u8; SECRET] {
    let mut xof = Shake256::new();
    xof.update(z);
    xof.update(c);
    let mut out = [0u8; SECRET];
    xof.finalize_xof().squeeze(&mut out);
    out
}

/// An encapsulation key taken apart for use: `t` decoded, the matrix
/// `A` sampled from `rho`, and `H(ek)`. None of it changes for the
/// life of the key, and remaking it was most of what an encapsulation
/// cost: nine or sixteen SHAKE-128 streams for `A`, and a SHA3-256
/// over the whole key. A key keeps it from the moment it is made.
#[derive(Clone)]
struct Expanded<const K: usize> {
    t: [Poly; K],
    /// `A[i][j]`, row first.
    a: [[Poly; K]; K],
    hash: [u8; 32],
}

/// Takes apart an encapsulation key already checked well formed.
fn expand<const K: usize>(ek: &[u8]) -> Expanded<K> {
    debug_assert_eq!(ek.len(), public_len(K));
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..]);
    let mut a = [[Poly::ZERO; K]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            *entry = Poly::sample_ntt(&rho, i as u8, j as u8);
        }
    }
    let mut t = [Poly::ZERO; K];
    for (i, t_i) in t.iter_mut().enumerate() {
        *t_i = Poly::decode(12, &ek[384 * i..384 * (i + 1)]);
    }
    Expanded { t, a, hash: h(ek) }
}

/// `K-PKE.KeyGen` and the wrapping of algorithm 16: the encapsulation
/// key into `ek` and the expanded decapsulation key into `dk`, from
/// the seed `d || z`. Returns the encapsulation key taken apart,
/// which the generation has already done most of.
fn key_gen<const K: usize>(
    seed: &[u8; SEED],
    ek: &mut [u8],
    dk: &mut [u8],
) -> Expanded<K> {
    debug_assert_eq!(ek.len(), public_len(K));
    debug_assert_eq!(dk.len(), private_len(K));
    let (d, z) = seed.split_at(32);
    let (rho, mut sigma) = g(&[d, &[K as u8]]);
    let eta1 = params::<K>().eta1;

    let mut s = [Poly::ZERO; K];
    let mut e = [Poly::ZERO; K];
    for (i, s_i) in s.iter_mut().enumerate() {
        *s_i = Poly::sample_noise(eta1, &sigma, i as u8);
        s_i.ntt();
    }
    for (i, e_i) in e.iter_mut().enumerate() {
        *e_i = Poly::sample_noise(eta1, &sigma, (K + i) as u8);
        e_i.ntt();
    }
    sigma.zeroize();

    // t = A s + e.
    let mut a = [[Poly::ZERO; K]; K];
    let mut t = e;
    for (i, (row, t_i)) in a.iter_mut().zip(t.iter_mut()).enumerate() {
        for (j, (entry, s_j)) in row.iter_mut().zip(&s).enumerate() {
            *entry = Poly::sample_ntt(&rho, i as u8, j as u8);
            t_i.add_assign(&entry.mul_ntt(s_j));
        }
        t_i.encode(12, &mut ek[384 * i..384 * (i + 1)]);
    }
    ek[384 * K..].copy_from_slice(&rho);

    for (i, s_i) in s.iter().enumerate() {
        s_i.encode(12, &mut dk[384 * i..384 * (i + 1)]);
    }
    let hash = h(ek);
    let rest = &mut dk[384 * K..];
    rest[..public_len(K)].copy_from_slice(ek);
    rest[public_len(K)..public_len(K) + 32].copy_from_slice(&hash);
    rest[public_len(K) + 32..].copy_from_slice(z);
    s.zeroize();
    e.zeroize();
    Expanded { t, a, hash }
}

/// `K-PKE.Encrypt`, algorithm 14: the message `m` under `ek`, taken
/// apart, with randomness `r`, into `c`.
fn encrypt<const K: usize>(
    ek: &Expanded<K>,
    m: &[u8; 32],
    r: &[u8; 32],
    c: &mut [u8],
) {
    let p = params::<K>();
    debug_assert_eq!(c.len(), ciphertext_len(K, p));

    let mut y = [Poly::ZERO; K];
    for (i, y_i) in y.iter_mut().enumerate() {
        *y_i = Poly::sample_noise(p.eta1, r, i as u8);
        y_i.ntt();
    }
    // u = A^T y + e1: the transpose, so A's row index is the inner
    // one.
    for i in 0..K {
        let mut u = Poly::ZERO;
        for (row, y_j) in ek.a.iter().zip(&y) {
            u.add_assign(&row[i].mul_ntt(y_j));
        }
        u.inverse_ntt();
        let e1 = Poly::sample_noise(p.eta2, r, (K + i) as u8);
        u.add_assign(&e1);
        u.compress(p.du)
            .encode(p.du, &mut c[32 * p.du * i..32 * p.du * (i + 1)]);
    }
    // v = t . y + e2 + Decompress_1(m).
    let mut v = Poly::ZERO;
    for (t_i, y_i) in ek.t.iter().zip(&y) {
        v.add_assign(&t_i.mul_ntt(y_i));
    }
    v.inverse_ntt();
    let e2 = Poly::sample_noise(p.eta2, r, (2 * K) as u8);
    v.add_assign(&e2);
    v.add_assign(&Poly::decode(1, m).decompress(1));
    v.compress(p.dv).encode(p.dv, &mut c[32 * p.du * K..]);
    y.zeroize();
}

/// `K-PKE.Decrypt`, algorithm 15: the message from `c` under the
/// secret polynomials at the front of `dk`.
fn decrypt<const K: usize>(dk: &[u8], c: &[u8]) -> [u8; 32] {
    let p = params::<K>();
    let mut v = Poly::decode(p.dv, &c[32 * p.du * K..]).decompress(p.dv);
    let mut w = Poly::ZERO;
    for i in 0..K {
        let mut u = Poly::decode(p.du, &c[32 * p.du * i..32 * p.du * (i + 1)])
            .decompress(p.du);
        u.ntt();
        let mut s = Poly::decode(12, &dk[384 * i..384 * (i + 1)]);
        w.add_assign(&s.mul_ntt(&u));
        // A polynomial of the private key, copied out of it.
        s.zeroize();
        u.zeroize();
    }
    w.inverse_ntt();
    v.sub_assign(&w);
    let mut m = [0u8; 32];
    v.compress(1).encode(1, &mut m);
    w.zeroize();
    v.zeroize();
    m
}

/// `ML-KEM.Encaps_internal`, algorithm 17: the ciphertext into `c`
/// and the shared secret returned, from the message `m`.
fn encapsulate<const K: usize>(
    ek: &Expanded<K>,
    m: &[u8; 32],
    c: &mut [u8],
) -> [u8; SECRET] {
    let (key, mut r) = g(&[m, &ek.hash]);
    encrypt::<K>(ek, m, &r, c);
    r.zeroize();
    key
}

/// `ML-KEM.Decaps_internal`, algorithm 18, with the implicit
/// rejection chosen by a mask.
fn decapsulate<const K: usize>(
    dk: &[u8],
    ek: &Expanded<K>,
    c: &[u8],
) -> [u8; SECRET] {
    let hash = &dk[384 * K + public_len(K)..384 * K + public_len(K) + 32];
    let z = &dk[384 * K + public_len(K) + 32..];
    let mut m = decrypt::<K>(dk, c);
    let (mut key, mut r) = g(&[&m, hash]);
    let mut rejected = j(z, c);
    let mut again = [0u8; 1568];
    let again = &mut again[..c.len()];
    encrypt::<K>(ek, &m, &r, again);
    // Both secrets are in hand; the comparison picks one without
    // saying which, or when.
    let same = constant_time::equal(c, again);
    let mask = (same as u8).wrapping_neg();
    for (k, rej) in key.iter_mut().zip(&rejected) {
        *k = (*k & mask) | (rej & !mask);
    }
    m.zeroize();
    r.zeroize();
    again.zeroize();
    // Derived from the long-term rejection secret `z`, so it outlives
    // the message it was for unless it goes here.
    rejected.zeroize();
    key
}

/// The parameters of the set with rank `K`.
const fn params<const K: usize>() -> &'static Params {
    match K {
        2 => &PARAMS_512,
        3 => &PARAMS_768,
        _ => &PARAMS_1024,
    }
}

/// The encapsulation key check of algorithm 20: every coefficient
/// below the modulus, which decoding and re-encoding tells.
fn public_key_is_valid<const K: usize>(ek: &[u8]) -> bool {
    let mut again = [0u8; 384];
    (0..K).all(|i| {
        let chunk = &ek[384 * i..384 * (i + 1)];
        Poly::decode(12, chunk).encode(12, &mut again);
        again[..] == chunk[..]
    })
}

/// The decapsulation key check of algorithm 21: the hash inside
/// matches the encapsulation key inside.
fn private_key_is_valid<const K: usize>(dk: &[u8]) -> bool {
    let ek = &dk[384 * K..384 * K + public_len(K)];
    let hash = &dk[384 * K + public_len(K)..384 * K + public_len(K) + 32];
    h(ek)[..] == hash[..]
}

// Formats: RFC 9935, which puts the bare encapsulation key in a
// SubjectPublicKeyInfo and one of the seed, the expanded key or both
// in PKCS#8, under the parameter set's own OID and no parameters.

/// The OID prefix of the three parameter sets,
/// 2.16.840.1.101.3.4.4; the last arc is 1, 2 or 3.
pub(crate) const OID_PREFIX: [u8; 8] =
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04];

/// Room for any encoding of any key here: an expanded ML-KEM-1024
/// key with both forms is under this.
const SCRATCH: usize = 4096;

const PRIVATE_LABEL: &str = "PRIVATE KEY";
const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// One parameter set's public types.
macro_rules! parameter_set {
    ($k:literal, $arc:literal, $name:literal) => {
        use zeroize::Zeroize;

        use crate::der::SeedOrExpanded;
        use crate::kem::ml_kem::{self, params};
        use crate::Random;
        use crate::Error;

        /// The length of a private key's seed, `d || z`, the form to
        /// store.
        pub const SEED_SIZE: usize = 64;

        /// The length of an expanded private key, FIPS 203's
        /// decapsulation key.
        pub const KEY_SIZE: usize = 768 * $k + 96;

        /// The length of a public key, FIPS 203's encapsulation key.
        pub const PUBLIC_KEY_SIZE: usize = 384 * $k + 32;

        /// The length of a ciphertext.
        pub const CIPHERTEXT_SIZE: usize =
            32 * (params::<$k>().du * $k + params::<$k>().dv);

        /// The length of a shared secret.
        pub const SHARED_SECRET_SIZE: usize = 32;

        /// The last arc of the parameter set's OID under
        /// 2.16.840.1.101.3.4.4.
        const OID: [u8; 9] = {
            let mut oid = [0u8; 9];
            let mut i = 0;
            while i < 8 {
                oid[i] = ml_kem::OID_PREFIX[i];
                i += 1;
            }
            oid[8] = $arc;
            oid
        };

        /// The most a private key's DER encoding can be: a PKCS#8
        /// `PrivateKeyInfo` around the expanded key. A key that has
        /// its seed is written as the seed instead, which is
        /// shorter; a buffer this long takes either.
        pub const DER_SIZE: usize =
            crate::der::pkcs8_len(OID.len(), crate::der::tlv_len(KEY_SIZE));

        /// The length of a public key's DER encoding, a
        /// `SubjectPublicKeyInfo`.
        pub const PUBLIC_KEY_DER_SIZE: usize =
            crate::der::spki_len(OID.len(), PUBLIC_KEY_SIZE);

        /// The length of a public key's PEM encoding, a `PUBLIC KEY`
        /// block.
        pub const PUBLIC_KEY_PEM_SIZE: usize =
            crate::codec::pem::encoded_len("PUBLIC KEY", PUBLIC_KEY_DER_SIZE);

        /// The length of a private key's PEM encoding, a `PRIVATE
        /// KEY` block around the DER above; the most it can be, as
        /// [`DER_SIZE`] is.
        pub const PEM_SIZE: usize =
            crate::codec::pem::encoded_len("PRIVATE KEY", DER_SIZE);

        #[doc = concat!("An ", $name, " private key, FIPS 203's")]
        /// decapsulation key, with its seed when it was made from
        /// one; wiped on drop.
        pub struct PrivateKey {
            seed: Option<[u8; SEED_SIZE]>,
            expanded: [u8; KEY_SIZE],
            public: PublicKey,
        }

        #[doc = concat!("An ", $name, " public key, FIPS 203's")]
        /// encapsulation key, checked to be well formed.
        #[derive(Clone)]
        pub struct PublicKey {
            bytes: [u8; PUBLIC_KEY_SIZE],
            expanded: ml_kem::Expanded<$k>,
        }

        impl Drop for PrivateKey {
            fn drop(&mut self) {
                self.seed.zeroize();
                self.expanded.zeroize();
            }
        }

        impl PrivateKey {
            fn from_expanded(
                seed: Option<[u8; SEED_SIZE]>,
                expanded: [u8; KEY_SIZE],
                public: ml_kem::Expanded<$k>,
            ) -> Self {
                let mut bytes = [0u8; PUBLIC_KEY_SIZE];
                bytes.copy_from_slice(
                    &expanded[384 * $k..384 * $k + PUBLIC_KEY_SIZE],
                );
                PrivateKey {
                    seed,
                    expanded,
                    public: PublicKey {
                        bytes,
                        expanded: public,
                    },
                }
            }

            /// A fresh key from 64 random bytes of seed.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let mut seed = [0u8; SEED_SIZE];
                rng.fill(&mut seed)?;
                let key = Self::from_seed(&seed);
                seed.zeroize();
                Ok(key)
            }

            /// The key a seed `d || z` expands to, by FIPS 203's
            /// `ML-KEM.KeyGen_internal`. Any 64 bytes are a seed,
            /// so there is nothing to reject.
            pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
                let mut expanded = [0u8; KEY_SIZE];
                let mut ek = [0u8; PUBLIC_KEY_SIZE];
                let public =
                    ml_kem::key_gen::<$k>(seed, &mut ek, &mut expanded);
                Self::from_expanded(Some(*seed), expanded, public)
            }

            /// A key from its expanded form, checked as FIPS 203
            /// requires: the hash inside must match the public key
            /// inside, and that key must be well formed. A key that
            /// comes in this way has no seed to give back.
            pub fn try_new(expanded: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                let ek = &expanded[384 * $k..384 * $k + PUBLIC_KEY_SIZE];
                if !ml_kem::private_key_is_valid::<$k>(expanded)
                    || !ml_kem::public_key_is_valid::<$k>(ek)
                {
                    return Err(Error::InvalidPrivateKey);
                }
                let public = ml_kem::expand::<$k>(ek);
                Ok(Self::from_expanded(None, *expanded, public))
            }

            /// The seed, when the key was made from one, and
            /// [`Error::InvalidPrivateKey`] when it came in expanded
            /// and has none. The caller holds a secret now.
            pub fn seed_bytes(&self) -> Result<[u8; SEED_SIZE], Error> {
                self.seed.ok_or(Error::InvalidPrivateKey)
            }

            /// The expanded form. The caller holds a secret now, and
            /// should wipe it when done.
            pub fn key_bytes(&self) -> [u8; KEY_SIZE] {
                self.expanded
            }

            /// The public half.
            pub fn public_key(&self) -> &PublicKey {
                &self.public
            }

            /// The shared secret a ciphertext carries.
            ///
            /// This cannot fail on a ciphertext of the right length:
            /// one that was not made for this key yields a secret
            /// derived from the ciphertext and a hidden value, which
            /// matches nothing the sender holds, so a forgery learns
            /// nothing from the outcome. That is FIPS 203's implicit
            /// rejection, and the reason there is no error to return.
            pub fn decapsulate(
                &self,
                ciphertext: &[u8; CIPHERTEXT_SIZE],
            ) -> [u8; SHARED_SECRET_SIZE] {
                ml_kem::decapsulate::<$k>(
                    &self.expanded,
                    &self.public.expanded,
                    ciphertext,
                )
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file, which holds the
            /// seed, the expanded key, or both; both are checked, and
            /// a pair that disagrees is [`Error::InconsistentKey`].
            /// Another parameter set is [`Error::WrongAlgorithm`], and
            /// anything else wrong with the bytes
            /// [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let info = crate::der::read_pkcs8(der)?;
                let algorithm = &info.algorithm;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::WrongAlgorithm);
                }
                let SeedOrExpanded { seed, expanded } =
                    crate::der::read_seed_or_expanded(info.private_key)?;
                let key = match (seed, expanded) {
                    (Some(seed), expanded) => {
                        let seed: &[u8; SEED_SIZE] = seed
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        let key = Self::from_seed(seed);
                        if expanded.is_some_and(|e| e[..] != key.expanded[..]) {
                            return Err(Error::InvalidEncoding);
                        }
                        key
                    }
                    (None, Some(expanded)) => {
                        let expanded: &[u8; KEY_SIZE] = expanded
                            .try_into()
                            .map_err(|_| Error::InvalidEncoding)?;
                        Self::try_new(expanded)?
                    }
                    (None, None) => return Err(Error::InvalidEncoding),
                };
                Ok(key)
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length: the seed when the key has
            /// one, since that is the form to store, and the expanded
            /// key otherwise. The output is a secret, to be wiped.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let seed_tag = crate::der::context_primitive(0);
                crate::der::write_pkcs8(out, &OID, false, |w| {
                    match &self.seed {
                        Some(seed) => w.primitive(seed_tag, seed),
                        None => w.octet_string(&self.expanded),
                    }
                })
            }

            /// A key from a `PRIVATE KEY` PEM block (RFC 7468) around
            /// the DER above; whitespace and line ends are read
            /// leniently, and anything else that is not exactly one
            /// well-formed block is [`Error::InvalidEncoding`].
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let labels = [ml_kem::PRIVATE_LABEL];
                let result = crate::codec::pem::decode_one_of(
                    &labels, pem, &mut der,
                )
                    .and_then(|(_, n)| Self::try_from_der(&der[..n]));
                der.zeroize();
                result
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let label = ml_kem::PRIVATE_LABEL;
                let result = self
                    .der_bytes(&mut der)
                    .and_then(|n| {
                        crate::codec::pem::encode(label, &der[..n], out)
                    });
                der.zeroize();
                result
            }
        }

        impl PublicKey {
            /// A public key from its bytes, checked as FIPS 203
            /// requires: every coefficient below the modulus.
            pub fn try_new(
                bytes: &[u8; PUBLIC_KEY_SIZE],
            ) -> Result<Self, Error> {
                if !ml_kem::public_key_is_valid::<$k>(bytes) {
                    return Err(Error::InvalidPublicKey);
                }
                Ok(PublicKey {
                    bytes: *bytes,
                    expanded: ml_kem::expand::<$k>(bytes),
                })
            }

            /// The key's bytes, FIPS 203's encapsulation key.
            pub fn bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                self.bytes
            }

            /// A ciphertext and the shared secret it carries, from 32
            /// random bytes; the holder of the private key recovers
            /// the secret from the ciphertext alone.
            pub fn encapsulate<R: Random>(
                &self,
                rng: &mut R,
            ) -> Result<
                ([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]),
                Error,
            > {
                let mut m = [0u8; 32];
                rng.fill(&mut m)?;
                let mut c = [0u8; CIPHERTEXT_SIZE];
                let secret =
                    ml_kem::encapsulate::<$k>(&self.expanded, &m, &mut c);
                m.zeroize();
                Ok((c, secret))
            }

            /// A key from its DER `SubjectPublicKeyInfo`, the form
            /// under `PUBLIC KEY` in a PEM file, which must name this
            /// parameter set.
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let (algorithm, key) = crate::der::read_spki(der)?;
                if algorithm.oid != OID || !algorithm.params.is_empty() {
                    return Err(Error::WrongAlgorithm);
                }
                let key: &[u8; PUBLIC_KEY_SIZE] =
                    key.try_into().map_err(|_| Error::InvalidEncoding)?;
                Self::try_new(key)
            }

            /// Writes the key as a `SubjectPublicKeyInfo` into the
            /// front of `out`, returning the length.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                crate::der::write_spki(out, &OID, false, |w| w.raw(&self.bytes))
            }

            /// A key from a `PUBLIC KEY` PEM block, read as
            /// [`PrivateKey::try_from_pem`] reads its own.
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let (_, n) =
                    crate::codec::pem::decode_one_of(
                        &[ml_kem::PUBLIC_LABEL],
                        pem,
                        &mut der,
                    )?;
                Self::try_from_der(&der[..n])
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let mut der = [0u8; ml_kem::SCRATCH];
                let n = self.der_bytes(&mut der)?;
                crate::codec::pem::encode(ml_kem::PUBLIC_LABEL, &der[..n], out)
            }
        }
    };
}

/// ML-KEM-512: security category 1, the smallest keys.
pub mod ml_kem_512 {
    parameter_set!(2, 1, "ML-KEM-512");
}

/// ML-KEM-768: security category 3, the set most deployments use.
pub mod ml_kem_768 {
    parameter_set!(3, 2, "ML-KEM-768");
}

/// ML-KEM-1024: security category 5.
pub mod ml_kem_1024 {
    parameter_set!(4, 3, "ML-KEM-1024");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, der};

    /// The word-at-a-time sampler agrees with algorithm 8 read bit
    /// by bit, at both widths.
    #[test]
    fn cbd_matches_the_definition() {
        for eta in [2usize, 3] {
            let bytes: std::vec::Vec<u8> = (0..64 * eta)
                .map(|i| (i as u8).wrapping_mul(97).wrapping_add(31))
                .collect();
            let bit = |n: usize| u16::from((bytes[n / 8] >> (n % 8)) & 1);
            let got = Poly::sample_cbd(eta, &bytes);
            for i in 0..N {
                let x: u16 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
                let y: u16 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
                assert_eq!(got.0[i], sub(x, y), "eta {eta} coefficient {i}");
            }
        }
    }

    /// The transform inverts, and the transform-domain product is
    /// the schoolbook product modulo x^256 + 1.
    #[test]
    fn ring_arithmetic() {
        let mut f = Poly::ZERO;
        let mut g = Poly::ZERO;
        for i in 0..N {
            f.0[i] = ((i * 7919 + 13) % Q as usize) as u16;
            g.0[i] = ((i * i + 5) % Q as usize) as u16;
        }
        let mut back = f;
        back.ntt();
        back.inverse_ntt();
        assert_eq!(back.0, f.0);

        let mut expected = Poly::ZERO;
        for i in 0..N {
            for k in 0..N {
                let c = mul(f.0[i], g.0[k]);
                // x^256 = -1.
                if i + k < N {
                    expected.0[i + k] = add(expected.0[i + k], c);
                } else {
                    expected.0[i + k - N] = sub(expected.0[i + k - N], c);
                }
            }
        }
        let (mut fh, mut gh) = (f, g);
        fh.ntt();
        gh.ntt();
        let mut product = fh.mul_ntt(&gh);
        product.inverse_ntt();
        assert_eq!(product.0, expected.0);
    }

    /// Every value below 2^26 reduces as plain division says.
    #[test]
    fn reductions() {
        for a in (0..1 << 26).step_by(9973) {
            assert_eq!(u32::from(reduce(a)), a % Q, "{a}");
        }
        assert_eq!(u32::from(reduce((1 << 26) - 1)), ((1 << 26) - 1) % Q);
        for a in 0..2 * Q {
            assert_eq!(u32::from(csub(a)), a % Q);
        }
        assert_eq!(ZETAS[1], 1729);
        assert_eq!(GAMMAS[0], 17);
    }

    /// Encoding and decoding invert at every width, and compression
    /// round-trips through decompression.
    #[test]
    fn encodings() {
        for d in [1usize, 4, 5, 10, 11, 12] {
            let mut f = Poly::ZERO;
            for (i, c) in f.0.iter_mut().enumerate() {
                *c = ((i * 2731 + 17) % (1 << d)) as u16;
                if d == 12 {
                    *c %= Q as u16;
                }
            }
            let mut bytes = [0u8; 384];
            f.encode(d, &mut bytes[..32 * d]);
            assert_eq!(Poly::decode(d, &bytes[..32 * d]).0, f.0, "d = {d}");
            if d < 12 {
                let round = f.decompress(d).compress(d);
                assert_eq!(round.0, f.0, "d = {d}");
            }
        }
    }

    /// Both directions agree on all three sets, a seed gives the
    /// same key twice, and a damaged ciphertext gives the rejection
    /// secret rather than an error or the real one.
    #[test]
    fn round_trips_and_rejection() {
        macro_rules! check {
            ($module:ident) => {{
                use $module::*;
                let mut rng = crate::random::CtrDrbg::from_system().unwrap();
                let key = PrivateKey::generate(&mut rng).unwrap();
                let (c, k) = key.public_key().encapsulate(&mut rng).unwrap();
                assert_eq!(key.decapsulate(&c), k);
                let again = PrivateKey::from_seed(&key.seed_bytes().unwrap());
                assert_eq!(again.key_bytes(), key.key_bytes());
                let expanded = PrivateKey::try_new(&key.key_bytes()).unwrap();
                assert_eq!(expanded.decapsulate(&c), k);
                assert_eq!(
                    expanded.seed_bytes(),
                    Err(Error::InvalidPrivateKey)
                );

                let mut bad = c;
                bad[3] ^= 1;
                let rejected = key.decapsulate(&bad);
                assert_ne!(rejected, k);
                let z = &key.key_bytes()[KEY_SIZE - 32..];
                assert_eq!(rejected, j(z, &bad));

                // A public key with a coefficient at the modulus is
                // refused; a private key with a wrong hash is refused.
                let mut ek = key.public_key().bytes();
                ek[0] = 0x01;
                ek[1] = 0x0d;
                assert_eq!(
                    PublicKey::try_new(&ek).err(),
                    Some(Error::InvalidPublicKey)
                );
                let mut dk = key.key_bytes();
                dk[KEY_SIZE - 40] ^= 1;
                assert_eq!(
                    PrivateKey::try_new(&dk).err(),
                    Some(Error::InvalidPrivateKey)
                );

                // DER and PEM, in the seed form and the expanded form.
                let mut out = [0u8; 6000];
                let n = key.der_bytes(&mut out).unwrap();
                assert_eq!(n, 2 + 3 + 13 + 2 + 2 + 64);
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.seed_bytes(), key.seed_bytes());
                let n = expanded.der_bytes(&mut out).unwrap();
                assert_eq!(n, DER_SIZE);
                let back = PrivateKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = key.pem_bytes(&mut out).unwrap();
                assert!(n < PEM_SIZE);
                assert!(out.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
                let back = PrivateKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.key_bytes(), key.key_bytes());
                let n = expanded.pem_bytes(&mut out).unwrap();
                assert_eq!(n, PEM_SIZE);
                let n = key.public_key().der_bytes(&mut out).unwrap();
                assert_eq!(n, PUBLIC_KEY_DER_SIZE);
                let back = PublicKey::try_from_der(&out[..n]).unwrap();
                assert_eq!(back.bytes(), key.public_key().bytes());
                let n = key.public_key().pem_bytes(&mut out).unwrap();
                assert_eq!(n, PUBLIC_KEY_PEM_SIZE);
                let back = PublicKey::try_from_pem(&out[..n]).unwrap();
                assert_eq!(back.bytes(), key.public_key().bytes());
            }};
        }
        check!(ml_kem_512);
        check!(ml_kem_768);
        check!(ml_kem_1024);
    }

    /// A key of one set is not a key of another, in either format.
    #[test]
    fn sets_do_not_mix() {
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let key = ml_kem_512::PrivateKey::generate(&mut rng).unwrap();
        let mut out = [0u8; 2048];
        let n = key.der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_kem_768::PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );
        let n = key.public_key().der_bytes(&mut out).unwrap();
        assert_eq!(
            ml_kem_768::PublicKey::try_from_der(&out[..n]).err(),
            Some(Error::WrongAlgorithm)
        );
    }

    /// The `both` form of the private key, a SEQUENCE of the seed and
    /// the expanded key as plain OCTET STRINGs (RFC 9935), reads, and
    /// is refused when its halves disagree.
    #[test]
    fn both_forms() {
        use ml_kem_768::*;
        let seed = [7u8; 64];
        let key = PrivateKey::from_seed(&seed);
        let expanded = key.key_bytes();
        let mut out = [0u8; 4096];
        let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02];
        let n = der::write_pkcs8(&mut out, &oid, false, |w| {
            w.sequence(|w| {
                w.octet_string(&seed);
                w.octet_string(&expanded);
            })
        })
        .unwrap();
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).unwrap().key_bytes(),
            expanded
        );
        let pos = out[..n].windows(64).position(|w| w == seed).unwrap();
        out[pos] ^= 1;
        assert_eq!(
            PrivateKey::try_from_der(&out[..n]).err(),
            Some(Error::InvalidEncoding)
        );
    }

    /// RFC 9935 appendix C.1.1: one ML-KEM-512 key in each of the
    /// three private key forms, which must all be the same key.
    #[test]
    fn rfc9935_private_key_forms() {
        const RFC9935_SEED: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ\n\
        GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\n\
        -----END PRIVATE KEY-----\n";
        const RFC9935_EXPANDED: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        MIIGeAIBADALBglghkgBZQMEBAEEggZkBIIGYHBVT9Q2NE8nhbGzsbrBhLZnkAMz\n\
        bCbxWn3oeMSCXGvgPzxKSA91t0hqrTHToAUYYj/SB6tSjdYnIUlYNa4AYsNnt0px\n\
        uvEKrQ6KKQIHa+MTSL6xXMwJV83rtK/yJnVrvGAbZWireErLrrNHAvD4aiYgIRiy\n\
        KyP4NVh3bHnBTbqYM3nIA+DcwxYKEXVwMOacaRl5jYHraYqaRIOpnlpcssMcmmYX\n\
        mfPMiceQcG6gQWKQRdQqg67YiGDjlMaRh+IQXSjMFOw5NZLWfdAKpD/otOrkQUAC\n\
        hmtccTxqjX0Wz3i4GdbxLp5adCM5CPCxXjxLqDKcXN2lXISSjjqoBj5aqWdkA/kX\n\
        NbEQEMf1kwkTZNyGRFvIBIQKmiFyQhJGn4p7DOCsaY64bK05p/SCTZpRY6rCHuaA\n\
        iwU8ij+ssLZ0S1Jiu8smpD9mTIcytkz8es8JlgX0HHlgYJdqxDODP+ADQ/sYKDAK\n\
        QkdBEW5LRbsnbqgRKaDbTG5gvOYREB6MYlR0kl4CImeTCKPncI0Zcqe0I+sjKFHD\n\
        bS7VPT7Tu3UAY3BhpdwikvocRmwHNUaDMovsLB7Sy1yZt47KCWkDjPfDTdEYck4x\n\
        yuCGIGs0MCtSD10Xet7Vs8zgKszoCOomvMByYl/bk/F0WKX8HU2jlDgKH1fpzGYQ\n\
        lDigdfDSgT/MShmcx22zgj8nCwBhWUGSlAQRo3/7r64sFQFlzsXGv3PFlfuSzRUx\n\
        JgfaBwd4ZSvZlEvEi8fRpTQzi60LrWZWxdUCznhQqxWHJE7rWPQ5q14IV0pxjIqs\n\
        PXfHmLuhVCczvnNEjyP7cMDlNTonyIMixSGEk6+7OAhkNNbWCla6iH3UmMOrJqCH\n\
        CZOBWqakCXXyGK3KFYLWT/yGUvuzqab7wwT5GUX6Sq7yh4/XFd9wET0jefRIhvgS\n\
        yD/ytxmmnh7HSuSxWszTrtWlPOdqewmCRxYzuXPLQKGgAV0KQk+hGkecAjAXQ20q\n\
        KQDpk+taCgZ0AMf0qt8gH8T6MSZKY7rpXMjWXDmVgV5ZfRBDVc8pqlMzyTJRhp1b\n\
        zb5IcST2Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHm\n\
        vG+QsOSbaTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbW\n\
        f/mqvJdQPyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lA\n\
        k0Frg7gSTmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8\n\
        XSCVcuD8dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoE\n\
        ZM5BqLtEwtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRr\n\
        evpsRZMlJqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5\n\
        JPSQpaxUlfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6\n\
        tnVUAAUHgVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10z\n\
        gGocjicyr5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyek\n\
        b7U7oR3ly0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oX\n\
        thQzzRr4D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPM\n\
        FgCQPmUpNWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGm\n\
        gx1bVMC3kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9h\n\
        uqtxp6PTUZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2\n\
        NoPwS/egnMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3g\n\
        uBw7xZoGWhttY7JsgvEB/2SAY7N24rtsW3RV9lWlDC/q2t4VDvoODm82WuogISIj\n\
        JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==\n\
        -----END PRIVATE KEY-----\n";
        const RFC9935_BOTH: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        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\n\
        Pj8=\n\
        -----END PRIVATE KEY-----\n";
        use ml_kem_512::PrivateKey;
        let seed = PrivateKey::try_from_pem(RFC9935_SEED).unwrap();
        let expanded = PrivateKey::try_from_pem(RFC9935_EXPANDED).unwrap();
        let both = PrivateKey::try_from_pem(RFC9935_BOTH).unwrap();
        assert_eq!(seed.key_bytes(), expanded.key_bytes());
        assert_eq!(seed.key_bytes(), both.key_bytes());
        let mut want = [0u8; 64];
        for (i, b) in want.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(both.seed_bytes().unwrap(), want);
    }
}
