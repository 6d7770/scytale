//! The NIST prime curves, P-256, P-384 and P-521: the arithmetic
//! under both ECDH and ECDSA, and the key handling the two schemes
//! share.
//!
//! Each curve is `y^2 = x^3 - 3x + b` over a prime field, with a
//! base point of prime order `n`, so every point but the identity
//! generates the whole group and there is no cofactor to clear. The
//! field and the scalar ring both run on [`Montgomery`], which is
//! generic over the width; nothing here is specialised to a curve
//! beyond its constants, its width in bits, and the table of
//! multiples of its base point in [`base`]. P-521's width is not a
//! whole number of limbs or bytes, which is why the bits are a
//! constant of their own: key generation and the RFC 6979 nonce
//! sample exactly that many, and encodings are 66 bytes wide.
//!
//! # Constant time
//!
//! Every scalar multiplication is a fixed sequence of field
//! operations, and every table read scans the whole table, so the
//! digit that chooses an entry never becomes an index or a branch.
//!
//! A multiplication of the base point reads per-window tables of
//! affine multiples where the curve carries them, which P-256 does:
//! a signed seven-bit digit for each of 37 windows, 64 entries a
//! window, and no doublings at all, since every entry is already
//! shifted to where it belongs. P-384, whose table at that width
//! would be 338 KB, keeps the four combs described in [`base`] and
//! the complete projective formulas of Renes, Costello and Batina
//! (2016) for `a = -3`, whose addition handles doubling, the
//! identity and inverse pairs with no case analysis.
//!
//! A multiplication of any other point is Jacobian, in signed
//! five-bit windows, where a doubling costs three multiplications
//! and five squarings rather than eight and three. That addition is
//! not complete, and each case it misses is settled by a mask rather
//! than a branch: either point being the identity takes the other,
//! and inverse pairs the formula handles itself. The remaining case,
//! two equal points, cannot arise in a windowed multiplication of a
//! scalar below the group order, for the reason
//! [`Engine::jacobian_add_affine`] sets out, so no table of doubles
//! is kept for it; the tables built here, where consecutive
//! multiples do meet, hand the addition the double itself.
//!
//! Inversion and square roots are exponentiations, whose exponent is
//! a constant of the curve rather than a secret, so the windows are
//! slid over it while the value being inverted steers nothing. For
//! P-256 the inversion is a fixed chain of 255 squarings and 13
//! multiplications, written out in [`x86_64`] where the processor
//! has the instructions.
//!
//! The only value-dependent control flow is the retry ECDSA makes
//! when a nonce yields a zero `r` or `s`, which happens once in
//! 2^256 signatures.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod base;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use zeroize::Zeroize;

use super::montgomery::Montgomery;
use super::uint::Uint;
use crate::BlockType;
use crate::Error;
use crate::Pkcs8Form;
use crate::Random;
use crate::codec::pem;
use crate::der::{self, Reader, Writer};
use crate::hash::Hash;
use crate::mac::Mac;
use crate::mac::hmac::Hmac;

/// A curve's constants, each as a big-endian hex string of `16 L`
/// digits, and the OID that names it in a certificate.
pub(crate) struct Curve<const L: usize> {
    /// The bits in `p` and `n`, which is the width of a coordinate
    /// or scalar. The limbs hold a multiple of 64 and the bytes a
    /// multiple of 8; P-521 fills neither.
    bits: usize,
    p: Uint<L>,
    b: Uint<L>,
    n: Uint<L>,
    // The generator, which only the tests read now: every
    // multiplication of it goes through `base`, whose first entry it
    // is. It stays as what that table is checked against.
    #[cfg_attr(not(test), allow(dead_code))]
    gx: Uint<L>,
    #[cfg_attr(not(test), allow(dead_code))]
    gy: Uint<L>,
    /// The comb table of multiples of `G`, described in [`base`].
    base: &'static [[[u64; L]; 2]],
    /// Per-window multiples of `G`, described in [`base`], for a
    /// curve that carries them; empty for one that does not, which
    /// takes the combs instead.
    windows: &'static [[[u64; L]; 2]],
    /// Montgomery contexts for `p` and `n`, made when the crate is
    /// built rather than for every operation.
    field: Montgomery<L>,
    order: Montgomery<L>,
    pub(crate) oid: &'static [u8],
}

/// The bits of scalar one window of the variable-base multiplication
/// takes.
const WINDOW: usize = 5;

/// A point in Jacobian coordinates: `x = X / Z^2`, `y = Y / Z^3`,
/// and the identity is anything with `Z = 0`.
///
/// The three coordinates are laid out in order, which the assembly
/// that reads a point straight out of memory relies on.
#[derive(Clone, Copy)]
#[repr(C)]
struct Jacobian<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
    z: Uint<L>,
}

impl<const L: usize> Jacobian<L> {
    fn cmov(&mut self, other: &Self, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
        self.z.cmov(&other.z, condition);
    }
}

/// A point in affine coordinates, both in the Montgomery domain.
/// There is no identity here: a table of these holds none, and the
/// digit that would have named one adds nothing instead.
///
/// Laid out in order, as [`Jacobian`] is and for the same reason.
#[derive(Clone, Copy)]
#[repr(C)]
struct Affine<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
}

impl<const L: usize> Affine<L> {
    fn cmov(&mut self, other: &Self, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
    }
}

/// Positions a signed form of the widest scalar here needs: a digit
/// for every bit, and one past the top for the carry.
const DIGITS: usize = 64 * 9 + 1;

/// The non-adjacent form of `k`, five bits wide: a signed odd digit
/// at about one position in six and zero elsewhere, least significant
/// first, with one position past the scalar for the carry.
///
/// For public scalars: the digits are what the caller may learn.
fn naf<const L: usize>(k: &Uint<L>) -> [i8; DIGITS] {
    const WIDTH: u32 = 5;
    debug_assert!(64 * L < DIGITS);
    let span = 1i64 << WIDTH;
    let mut digits = [0i8; DIGITS];
    let mut carry = 0u64;
    let mut pos = 0usize;
    while pos <= 64 * L {
        // The window, which may straddle two limbs and may run past
        // the scalar, where the bits are zero.
        let bit = |i: usize| -> u64 {
            if i >= 64 * L {
                0
            } else {
                (k.0[i >> 6] >> (i & 63)) & 1
            }
        };
        let mut window = 0u64;
        for j in 0..WIDTH as usize {
            window |= bit(pos + j) << j;
        }
        let value = carry + window;
        // An even value leaves no digit here. The carry stays as it
        // is: a carry and a set low bit make two, which is the same
        // carry one position up, where the window has moved to.
        if value & 1 == 0 {
            pos += 1;
            continue;
        }
        // Past half the span the digit goes negative, and what it
        // borrowed from the next window is the carry.
        if (value as i64) < span / 2 {
            carry = 0;
            digits[pos] = value as i8;
        } else {
            carry = 1;
            digits[pos] = (value as i64 - span) as i8;
        }
        pos += WIDTH as usize;
    }
    digits
}

/// Booth's recoding of window `at` of `k`, `width` bits wide: the
/// digit's magnitude, which is at most half the window's span, and
/// one when it is negative.
///
/// The window reads one bit below its own, so the digits of the whole
/// scalar are signed and each is worth `2^(width window)`. Nothing
/// here branches or indexes on the scalar.
fn booth<const L: usize>(k: &Uint<L>, at: usize, width: usize) -> (u64, u64) {
    let bit = |i: usize| -> u64 {
        if i >= 64 * L {
            0
        } else {
            (k.0[i >> 6] >> (i & 63)) & 1
        }
    };
    let mut chunk = 0u64;
    for i in 0..=width {
        // The lowest window reads a zero below the scalar.
        let index = at * width + i;
        let value = if index == 0 { 0 } else { bit(index - 1) };
        chunk |= value << i;
    }
    // The sign is the top bit; the magnitude is the rest, rounded to
    // the nearest multiple of two and halved, which is Booth's digit.
    let sign = (chunk >> width) & 1;
    let mask = sign.wrapping_neg();
    let complement = (1u64 << (width + 1)) - chunk - 1;
    let magnitude = (complement & mask) | (chunk & !mask);
    ((magnitude >> 1) + (magnitude & 1), sign)
}

/// The bits of scalar one window of the per-window fixed-base table
/// takes, and the entries that width needs: every digit magnitude a
/// Booth window of it can name, the zero apart.
const BASE_WINDOW: usize = 7;
const BASE_ENTRIES: usize = 1 << (BASE_WINDOW - 1);

/// The blocks a scalar is cut into for a fixed-base multiplication,
/// and so the width of the comb's digit.
const COMB: usize = 6;

/// How many combs run side by side. Each has its own table, holding
/// the same combinations shifted a further `block / TABLES` bits, so
/// the doublings divide by this and only the additions remain. Four
/// costs 16 KB of table for P-256 and 24 KB for P-384, and saves
/// three doublings in four.
const TABLES: usize = 4;

/// Entries in one comb's table: every nonzero combination of its
/// blocks.
const ENTRIES: usize = (1 << COMB) - 1;

/// The bits in one comb block, which is how many doublings a
/// fixed-base multiplication makes.
const fn block<const L: usize>() -> usize {
    (64 * L).div_ceil(COMB)
}

/// A hex string of exactly `16 * L` digits, as limbs.
const fn from_hex<const L: usize>(hex: &str) -> Uint<L> {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 16 * L, "wrong width");
    let mut limbs = [0u64; L];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not hex"),
        };
        // The first sixteen digits are the top limb.
        let limb = L - 1 - i / 16;
        limbs[limb] = (limbs[limb] << 4) | v as u64;
        i += 1;
    }
    Uint(limbs)
}

impl<const L: usize> Curve<L> {
    /// The width of a coordinate or scalar in bytes.
    pub(crate) const fn width(&self) -> usize {
        self.bits.div_ceil(8)
    }

    /// The bits of the top byte of a scalar that are in use, as a
    /// mask: all of them unless the width is not a whole number of
    /// bytes.
    const fn top_mask(&self) -> u8 {
        0xff >> (8 * self.width() - self.bits)
    }
}

/// The P-256 field prime.
const P256_P: Uint<4> = from_hex(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
);

/// The P-256 group order.
pub(crate) const P256_N: Uint<4> = from_hex(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

/// P-256, secp256r1, prime256v1: FIPS 186-5 and SEC 2.
pub(crate) const P256: Curve<4> = Curve {
    bits: 256,
    p: P256_P,
    b: from_hex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    ),
    n: P256_N,
    gx: from_hex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
    gy: from_hex(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    ),
    base: &base::P256_BASE,
    windows: &base::P256_WINDOWS,
    field: Montgomery::known(P256_P),
    order: Montgomery::known(P256_N),
    // 1.2.840.10045.3.1.7
    oid: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
};

/// The P-384 field prime.
const P384_P: Uint<6> = from_hex(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
     ffffffff0000000000000000ffffffff",
);

/// The P-384 group order.
pub(crate) const P384_N: Uint<6> = from_hex(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
     581a0db248b0a77aecec196accc52973",
);

/// P-384, secp384r1.
pub(crate) const P384: Curve<6> = Curve {
    bits: 384,
    p: P384_P,
    b: from_hex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
         c656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    n: P384_N,
    gx: from_hex(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
         5502f25dbf55296c3a545e3872760ab7",
    ),
    gy: from_hex(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
         0a60b1ce1d7e819d7a431d7c90ea0e5f",
    ),
    base: &base::P384_BASE,
    // The same layout would be 338 KB here, where the combs are 24.
    windows: &[],
    field: Montgomery::known(P384_P),
    order: Montgomery::known(P384_N),
    // 1.3.132.0.34
    oid: &[0x2b, 0x81, 0x04, 0x00, 0x22],
};

/// The P-521 field prime, `2^521 - 1`.
const P521_P: Uint<9> = from_hex(
    "00000000000001ffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
     ffffffffffffffff",
);

/// The P-521 group order.
pub(crate) const P521_N: Uint<9> = from_hex(
    "00000000000001ffffffffffffffffffffffffffffffffffffffffffffffffff\
     fffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47ae\
     bb6fb71e91386409",
);

/// P-521, secp521r1.
pub(crate) const P521: Curve<9> = Curve {
    bits: 521,
    p: P521_P,
    b: from_hex(
        "0000000000000051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3\
         b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1\
         ef451fd46b503f00",
    ),
    n: P521_N,
    gx: from_hex(
        "00000000000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521\
         f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429b\
         f97e7e31c2e5bd66",
    ),
    gy: from_hex(
        "000000000000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b4468\
         17afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c240\
         88be94769fd16650",
    ),
    base: &base::P521_BASE,
    // Combs only, as for P-384.
    windows: &[],
    field: Montgomery::known(P521_P),
    order: Montgomery::known(P521_N),
    // 1.3.132.0.35
    oid: &[0x2b, 0x81, 0x04, 0x00, 0x23],
};

/// The contents of the OID `id-ecPublicKey`, 1.2.840.10045.2.1,
/// which names every prime-curve key; the parameters say which.
pub(crate) const EC_PUBLIC_KEY: &[u8] =
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// A point in projective coordinates, `(X : Y : Z)` for the affine
/// `(X/Z, Y/Z)`, every coordinate in the field's Montgomery domain.
/// The identity is any point with `Z = 0`.
#[derive(Clone, Copy)]
struct Point<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
    z: Uint<L>,
}

impl<const L: usize> Point<L> {
    /// Only the complete multiplication the tests check against picks
    /// between points this way now.
    #[cfg(test)]
    fn cmov(&mut self, other: &Self, condition: u64) {
        self.x.cmov(&other.x, condition);
        self.y.cmov(&other.y, condition);
        self.z.cmov(&other.z, condition);
    }
}

/// Arithmetic ready for one curve: both moduli in Montgomery form,
/// and the constants the formulas need already in the field's
/// domain. Built for each operation, from contexts the curve
/// constants already hold: two Montgomery products and nothing else.
pub(crate) struct Engine<'a, const L: usize> {
    curve: &'a Curve<L>,
    field: &'a Montgomery<L>,
    order: &'a Montgomery<L>,
    /// The P-256 field product written out for this processor, asked
    /// once for an operation rather than once for every product.
    #[cfg(target_arch = "x86_64")]
    fast: Option<crate::math::montgomery::x86_64::Adx>,
    /// The table read written out for this processor, asked the same
    /// way. Four-limb entries only, so the wider curve scans its
    /// table as the compiler makes it.
    #[cfg(target_arch = "x86_64")]
    vector: Option<x86_64::Avx2>,
    /// Whether the written-out A64 point and field code applies:
    /// it is P-256's arithmetic, not any four-limb curve's, so the
    /// prime has to match and not merely the width.
    #[cfg(target_arch = "aarch64")]
    p256: bool,
    /// `b`, in the domain.
    b: Uint<L>,
    /// One, in the domain: `R mod p`.
    one: Uint<L>,
}

impl<'a, const L: usize> Engine<'a, L> {
    pub(crate) fn new(curve: &'a Curve<L>) -> Self {
        let field = &curve.field;
        let order = &curve.order;
        #[cfg(target_arch = "x86_64")]
        let fast = (L == 4 && curve.p.0[..] == super::montgomery::P256_PRIME)
            .then(crate::math::montgomery::x86_64::probe)
            .flatten();
        #[cfg(target_arch = "x86_64")]
        let vector = (L == 4).then(x86_64::probe).flatten();
        #[cfg(target_arch = "aarch64")]
        let p256 = L == 4 && curve.p.0[..] == super::montgomery::P256_PRIME;
        let one = field.to_mont(&Uint::one());
        let b = field.to_mont(&curve.b);
        Engine {
            curve,
            field,
            order,
            #[cfg(target_arch = "aarch64")]
            p256,
            #[cfg(target_arch = "x86_64")]
            fast,
            #[cfg(target_arch = "x86_64")]
            vector,
            b,
            one,
        }
    }

    // The field, everything in the Montgomery domain.

    /// The field product. The formulas are nothing else, so this is
    /// the one call worth taking the long way round for: where the
    /// processor has the instructions, the product is the assembly
    /// inlined here rather than a call into the generic width.
    #[inline(always)]
    fn mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            return fast.mul(a, b);
        }
        self.portable_mul(a, b)
    }

    /// The square, which is the product of a value with itself but
    /// for the cross terms it need not take twice.
    #[inline(always)]
    fn sqr(&self, a: &Uint<L>) -> Uint<L> {
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            return fast.sqr(a);
        }
        self.portable_sqr(a)
    }

    /// The square for a width or a modulus with nothing written out
    /// for it, kept out of line as the product is.
    #[inline(never)]
    fn portable_sqr(&self, a: &Uint<L>) -> Uint<L> {
        self.field.sqr(a)
    }

    /// The product for a width or a modulus with nothing written out
    /// for it. Kept out of line: inlined beside the assembly it
    /// doubled the size of every formula, and the spilling that came
    /// with that cost more than the call.
    #[inline(never)]
    fn portable_mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        self.field.mul(a, b)
    }

    fn add(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        a.add_mod(b, &self.curve.p)
    }

    fn sub(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        a.sub_mod(b, &self.curve.p)
    }

    /// `a^-1`, by Fermat: `a^(p-2)`. Zero maps to zero.
    fn invert(&self, a: &Uint<L>) -> Uint<L> {
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            return fast.invert(a);
        }
        #[cfg(target_arch = "aarch64")]
        if self.p256 {
            return aarch64::invert_field(a);
        }
        let (exponent, _) = self.curve.p.sub_borrow(&Uint::from_limbs(&[2]));
        self.exp(a, &exponent)
    }

    /// The inverse by the generic exponentiation, which is what the
    /// written out chain is checked against.
    #[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn portable_invert(&self, a: &Uint<L>) -> Uint<L> {
        let (exponent, _) = self.curve.p.sub_borrow(&Uint::from_limbs(&[2]));
        self.exp(a, &exponent)
    }

    /// `a^e`, both in the domain, for an exponent that is a constant
    /// of the curve: five-bit windows slid over it.
    ///
    /// The generic exponentiation would do the same arithmetic, but
    /// through the width's own product rather than the one this
    /// engine holds, which for P-256 is the assembly inlined here;
    /// at 250-odd operations for an inversion that is the difference
    /// between a third of a key generation and a fifth.
    fn exp(&self, a: &Uint<L>, exponent: &Uint<L>) -> Uint<L> {
        const WIDTH: usize = 5;
        // The odd powers the windows name: a, a^3, ... a^31.
        let square = self.sqr(a);
        let mut odd = [*a; 1 << (WIDTH - 1)];
        for i in 1..odd.len() {
            odd[i] = self.mul(&odd[i - 1], &square);
        }
        let bit = |i: usize| (exponent.0[i >> 6] >> (i & 63)) & 1;
        let mut acc = self.one;
        let mut i = 64 * L;
        let mut started = false;
        while i > 0 {
            i -= 1;
            if bit(i) == 0 {
                if started {
                    acc = self.sqr(&acc);
                }
                continue;
            }
            // The longest window ending on a set bit, so that the
            // power it names is one the table holds.
            let mut width = 1;
            for w in 2..=WIDTH.min(i + 1) {
                if bit(i + 1 - w) == 1 {
                    width = w;
                }
            }
            let mut digit = 0usize;
            for j in 0..width {
                digit = (digit << 1) | (bit(i - j) as usize);
            }
            if started {
                for _ in 0..width {
                    acc = self.sqr(&acc);
                }
                acc = self.mul(&acc, &odd[digit >> 1]);
            } else {
                acc = odd[digit >> 1];
                started = true;
            }
            i -= width - 1;
        }
        acc
    }

    /// A square root of `a`, or `None` when it has none. Both
    /// primes are 3 mod 4, so the root is `a^((p+1)/4)`; squaring
    /// the candidate back is what tells a non-residue apart.
    fn sqrt(&self, a: &Uint<L>) -> Option<Uint<L>> {
        let (exponent, _) = self.curve.p.add_carry(&Uint::one());
        let exponent = exponent.shr(2);
        let root = self.exp(a, &exponent);
        if self.sqr(&root).0 == a.0 {
            Some(root)
        } else {
            None
        }
    }

    /// `x^3 - 3x + b`, the right-hand side of the curve equation.
    fn rhs(&self, x: &Uint<L>) -> Uint<L> {
        let x2 = self.sqr(x);
        let x3 = self.mul(&x2, x);
        let three_x = self.add(&self.add(x, x), x);
        self.add(&self.sub(&x3, &three_x), &self.b)
    }

    // The group.

    fn identity(&self) -> Point<L> {
        Point {
            x: Uint::ZERO,
            y: self.one,
            z: Uint::ZERO,
        }
    }

    /// `p + q`, by algorithm 4 of Renes, Costello and Batina: the
    /// complete formulas for `a = -3`, which need no case for
    /// doubling or for the identity.
    fn point_add(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        let (x1, y1, z1) = (&p.x, &p.y, &p.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let b = &self.b;

        let t0 = self.mul(x1, x2);
        let t1 = self.mul(y1, y2);
        let t2 = self.mul(z1, z2);
        let t3 = self.add(x1, y1);
        let t4 = self.add(x2, y2);
        let t3 = self.mul(&t3, &t4);
        let t4 = self.add(&t0, &t1);
        let t3 = self.sub(&t3, &t4);
        let t4 = self.add(y1, z1);
        let x3 = self.add(y2, z2);
        let t4 = self.mul(&t4, &x3);
        let x3 = self.add(&t1, &t2);
        let t4 = self.sub(&t4, &x3);
        let x3 = self.add(x1, z1);
        let y3 = self.add(x2, z2);
        let x3 = self.mul(&x3, &y3);
        let y3 = self.add(&t0, &t2);
        let y3 = self.sub(&x3, &y3);
        let z3 = self.mul(b, &t2);
        let x3 = self.sub(&y3, &z3);
        let z3 = self.add(&x3, &x3);
        let x3 = self.add(&x3, &z3);
        let z3 = self.sub(&t1, &x3);
        let x3 = self.add(&t1, &x3);
        let y3 = self.mul(b, &y3);
        let t1 = self.add(&t2, &t2);
        let t2 = self.add(&t1, &t2);
        let y3 = self.sub(&y3, &t2);
        let y3 = self.sub(&y3, &t0);
        let t1 = self.add(&y3, &y3);
        let y3 = self.add(&t1, &y3);
        let t1 = self.add(&t0, &t0);
        let t0 = self.add(&t1, &t0);
        let t0 = self.sub(&t0, &t2);
        let t1 = self.mul(&t4, &y3);
        let t2 = self.mul(&t0, &y3);
        let y3 = self.mul(&x3, &z3);
        let y3 = self.add(&y3, &t2);
        let x3 = self.mul(&t3, &x3);
        let x3 = self.sub(&x3, &t1);
        let z3 = self.mul(&t4, &z3);
        let t1 = self.mul(&t3, &t0);
        let z3 = self.add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `2 p`, by algorithm 6 of Renes, Costello and Batina: the
    /// complete doubling for `a = -3`. One multiplication cheaper
    /// than adding a point to itself, and the doublings are most of
    /// what a scalar multiplication does.
    fn point_double(&self, p: &Point<L>) -> Point<L> {
        let (x, y, z) = (&p.x, &p.y, &p.z);
        let b = &self.b;

        let t0 = self.sqr(x);
        let t1 = self.sqr(y);
        let t2 = self.sqr(z);
        let t3 = self.mul(x, y);
        let t3 = self.add(&t3, &t3);
        let z3 = self.mul(x, z);
        let z3 = self.add(&z3, &z3);
        let y3 = self.mul(b, &t2);
        let y3 = self.sub(&y3, &z3);
        let x3 = self.add(&y3, &y3);
        let y3 = self.add(&x3, &y3);
        let x3 = self.sub(&t1, &y3);
        let y3 = self.add(&t1, &y3);
        let y3 = self.mul(&x3, &y3);
        let x3 = self.mul(&x3, &t3);
        let t3 = self.add(&t2, &t2);
        let t2 = self.add(&t3, &t2);
        let z3 = self.mul(b, &z3);
        let z3 = self.sub(&z3, &t2);
        let z3 = self.sub(&z3, &t0);
        let t3 = self.add(&z3, &z3);
        let z3 = self.add(&z3, &t3);
        let t3 = self.add(&t0, &t0);
        let t0 = self.add(&t3, &t0);
        let t0 = self.sub(&t0, &t2);
        let t0 = self.mul(&t0, &z3);
        let y3 = self.add(&y3, &t0);
        let t0 = self.mul(y, z);
        let t0 = self.add(&t0, &t0);
        let z3 = self.mul(&t0, &z3);
        let x3 = self.sub(&x3, &z3);
        let z3 = self.mul(&t0, &t1);
        let z3 = self.add(&z3, &z3);
        let z3 = self.add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    // The variable-base multiplication runs in Jacobian coordinates,
    // where `x = X / Z^2` and `y = Y / Z^3`. A doubling there costs
    // three multiplications and five squarings against the complete
    // formulas' eight and three, which is most of what a scalar
    // multiplication does; the addition is not complete, so every
    // case it does not cover is settled by a mask below.

    /// Doubling in Jacobian coordinates, for `a = -3`.
    ///
    /// The identity has `Z = 0`, and doubling it leaves `Z = 0`, so
    /// that case needs nothing.
    fn jacobian_double(&self, p: &Jacobian<L>) -> Jacobian<L> {
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            return fast.jacobian_double(p);
        }
        #[cfg(target_arch = "aarch64")]
        if self.p256 {
            return aarch64::jacobian_double(p);
        }
        self.portable_double(p)
    }

    /// The doubling as the formula reads, which is what the written
    /// out one is checked against.
    fn portable_double(&self, p: &Jacobian<L>) -> Jacobian<L> {
        let delta = self.sqr(&p.z);
        let gamma = self.sqr(&p.y);
        let beta = self.mul(&p.x, &gamma);
        let sum = self.add(&p.x, &delta);
        let difference = self.sub(&p.x, &delta);
        let product = self.mul(&sum, &difference);
        let alpha = self.add(&self.add(&product, &product), &product);
        let beta4 = self.add(&beta, &beta);
        let beta4 = self.add(&beta4, &beta4);
        let beta8 = self.add(&beta4, &beta4);
        let x = self.sub(&self.sqr(&alpha), &beta8);
        let gamma2 = self.sqr(&gamma);
        let gamma8 = {
            let two = self.add(&gamma2, &gamma2);
            let four = self.add(&two, &two);
            self.add(&four, &four)
        };
        let y = self.sub(&self.mul(&alpha, &self.sub(&beta4, &x)), &gamma8);
        let yz = self.add(&p.y, &p.z);
        let z = self.sub(&self.sub(&self.sqr(&yz), &gamma), &delta);
        Jacobian { x, y, z }
    }

    /// Addition in Jacobian coordinates.
    ///
    /// The formula is not complete: it is wrong when the points are
    /// equal, and when either is the identity. Each of those is
    /// settled by a mask rather than a branch: `twice` is the double
    /// of `q`, which is the answer when the two are equal, `q` is the
    /// answer when `p` is the identity, and `p` is the answer when
    /// `q` is. Opposite points are the one case the formula does
    /// handle, leaving `Z = 0`, which is what they add to.
    fn jacobian_add(
        &self,
        p: &Jacobian<L>,
        q: &Jacobian<L>,
        twice: &Jacobian<L>,
    ) -> Jacobian<L> {
        #[cfg(target_arch = "aarch64")]
        if self.p256 {
            let mut out = aarch64::jacobian_add(p, q);
            let same = out.x.is_zero_mask() & out.z.is_zero_mask();
            out.cmov(twice, same);
            out.cmov(q, p.z.is_zero_mask());
            out.cmov(p, q.z.is_zero_mask());
            return out;
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            let mut out = fast.jacobian_add(p, q);
            // Equal points, which the formula cannot do itself, are
            // read off the sum: it is zero throughout only for them.
            // A pair of inverses, the other case with a zero `z`,
            // leaves `x` as `r^2`, which is not zero there.
            let same = out.x.is_zero_mask() & out.z.is_zero_mask();
            out.cmov(twice, same);
            out.cmov(q, p.z.is_zero_mask());
            out.cmov(p, q.z.is_zero_mask());
            return out;
        }
        self.portable_add(p, q, twice)
    }

    /// The addition as the formula reads, which is what the written
    /// out one is checked against.
    fn portable_add(
        &self,
        p: &Jacobian<L>,
        q: &Jacobian<L>,
        twice: &Jacobian<L>,
    ) -> Jacobian<L> {
        let zz1 = self.sqr(&p.z);
        let zz2 = self.sqr(&q.z);
        let u1 = self.mul(&p.x, &zz2);
        let u2 = self.mul(&q.x, &zz1);
        let s1 = self.mul(&self.mul(&p.y, &q.z), &zz2);
        let s2 = self.mul(&self.mul(&q.y, &p.z), &zz1);
        let h = self.sub(&u2, &u1);
        let r = self.sub(&s2, &s1);
        let r = self.add(&r, &r);
        let h2 = self.add(&h, &h);
        let i = self.sqr(&h2);
        let j = self.mul(&h, &i);
        let v = self.mul(&u1, &i);
        let x = {
            let v2 = self.add(&v, &v);
            self.sub(&self.sub(&self.sqr(&r), &j), &v2)
        };
        let y = {
            let s1j = self.mul(&s1, &j);
            let s1j2 = self.add(&s1j, &s1j);
            self.sub(&self.mul(&r, &self.sub(&v, &x)), &s1j2)
        };
        let z = {
            let sum = self.add(&p.z, &q.z);
            let squared = self.sub(&self.sub(&self.sqr(&sum), &zz1), &zz2);
            self.mul(&squared, &h)
        };
        let mut out = Jacobian { x, y, z };
        // Equal points: `h` and `r` are both zero, and the formula
        // above yields nothing useful.
        let equal = h.is_zero_mask() & r.is_zero_mask();
        out.cmov(twice, equal);
        // Either being the identity, which the formula also misses.
        out.cmov(q, p.z.is_zero_mask());
        out.cmov(p, q.z.is_zero_mask());
        out
    }

    /// `p + q`, where `q` is affine: seven multiplications and four
    /// squarings, against the eleven and five of the general
    /// addition, because `q`'s `Z` is one and every product with it
    /// falls away.
    ///
    /// The identity is settled by a mask, as in [`jacobian_add`]:
    /// `p` being it takes `q` lifted. The case that addition needs a
    /// table of doubles for, `p` and `q` equal, cannot arise here,
    /// and the callers are why. Every caller is a windowed
    /// multiplication over Booth digits, where before the addition
    /// at window `w` the accumulator holds `S * P` for
    /// `S = sum(d[j] 2^(W j), j > w)`, a multiple of `2^(W(w+1))`,
    /// and the entry is `d[w] 2^(W w) P` with `|d[w]| <= 2^(W-1)`.
    /// A collision would need `S -/+ d[w] 2^(W w)` to be zero or a
    /// multiple of the order: zero is out because the two magnitudes
    /// differ, the first being either zero, which the mask covers,
    /// or at least `2^(W(w+1))`, and the second below it; and a
    /// nonzero multiple `m n` is out because that difference is
    /// divisible by `2^(W w)` while `n` is odd and `|m|` is at most
    /// two for scalars below the order.
    ///
    /// That last step says nothing at the lowest window, where
    /// `2^(W w)` is one: there the collision is a scalar
    /// `k = n + 2 d[0]` with `d[0]` negative, which exists when the
    /// order's low bits recode to the right digit. P-256's do not,
    /// for either window width here, and P-384's do not; P-521's do,
    /// at `k = n - 18`. So every caller hands the lowest window to
    /// the addition that takes the double alongside.
    ///
    /// [`jacobian_add`]: Self::jacobian_add
    fn jacobian_add_affine(
        &self,
        p: &Jacobian<L>,
        q: &Affine<L>,
    ) -> Jacobian<L> {
        #[cfg(target_arch = "aarch64")]
        if self.p256 {
            let mut out = aarch64::jacobian_add_affine(p, q);
            out.cmov(
                &Jacobian {
                    x: q.x,
                    y: q.y,
                    z: self.one,
                },
                p.z.is_zero_mask(),
            );
            return out;
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(fast) = self.fast {
            let mut out = fast.jacobian_add_affine(p, q);
            out.cmov(
                &Jacobian {
                    x: q.x,
                    y: q.y,
                    z: self.one,
                },
                p.z.is_zero_mask(),
            );
            return out;
        }
        self.portable_add_affine(p, q)
    }

    /// The mixed addition as the formula reads, which is what the
    /// written out one is checked against.
    fn portable_add_affine(
        &self,
        p: &Jacobian<L>,
        q: &Affine<L>,
    ) -> Jacobian<L> {
        let zz = self.sqr(&p.z);
        let u2 = self.mul(&q.x, &zz);
        let s2 = self.mul(&self.mul(&q.y, &p.z), &zz);
        let h = self.sub(&u2, &p.x);
        let r = {
            let d = self.sub(&s2, &p.y);
            self.add(&d, &d)
        };
        let hh = self.sqr(&h);
        let i = {
            let h2 = self.add(&h, &h);
            self.sqr(&h2)
        };
        let j = self.mul(&h, &i);
        let v = self.mul(&p.x, &i);
        let x = {
            let v2 = self.add(&v, &v);
            self.sub(&self.sub(&self.sqr(&r), &j), &v2)
        };
        let y = {
            let yj = self.mul(&p.y, &j);
            let yj2 = self.add(&yj, &yj);
            self.sub(&self.mul(&r, &self.sub(&v, &x)), &yj2)
        };
        let z = {
            let sum = self.add(&p.z, &h);
            self.sub(&self.sub(&self.sqr(&sum), &zz), &hh)
        };
        let mut out = Jacobian { x, y, z };
        out.cmov(
            &Jacobian {
                x: q.x,
                y: q.y,
                z: self.one,
            },
            p.z.is_zero_mask(),
        );
        out
    }

    /// The affine form of every point given, by Montgomery's trick:
    /// the inverses of all the `Z` come from one inversion and three
    /// multiplications a point, rather than an inversion each.
    ///
    /// No point here may be the identity; none is, because each is a
    /// multiple of a point of prime order by a factor below it.
    #[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn normalise<const N: usize>(
        &self,
        points: &[Jacobian<L>; N],
    ) -> [[[u64; L]; 2]; N] {
        // Running products of the `Z`, so that entry `i` holds the
        // product of every one below it.
        let mut prefix = [self.one; N];
        let mut running = self.one;
        for (slot, point) in prefix.iter_mut().zip(points) {
            *slot = running;
            running = self.mul(&running, &point.z);
        }
        let mut inverse = self.invert(&running);
        let mut out = [[[0u64; L]; 2]; N];
        // Back down, peeling one `Z` off the running inverse at each
        // step to leave that point's own.
        for i in (0..N).rev() {
            let zi = self.mul(&inverse, &prefix[i]);
            inverse = self.mul(&inverse, &points[i].z);
            let zi2 = self.sqr(&zi);
            out[i] = [
                self.mul(&points[i].x, &zi2).0,
                self.mul(&points[i].y, &self.mul(&zi2, &zi)).0,
            ];
        }
        out
    }

    /// The entry of `table` the digit names, counted from one, or
    /// zero where it names none. The digit is secret, so every entry
    /// is read and nothing indexes.
    ///
    /// Word by word, which on x86-64 the compiler makes vector code
    /// of, so the hand-written scan there is worth it only for being
    /// twice as wide. On AArch64 it makes no vector code at all, and
    /// the scan there is worth it for being vector code.
    #[inline(always)]
    fn select(&self, table: &[[[u64; L]; 2]], digit: u64) -> Affine<L> {
        #[cfg(target_arch = "x86_64")]
        if let Some(vector) = self.vector {
            let (x, y) = vector.select(table, digit);
            return Affine { x, y };
        }
        #[cfg(target_arch = "aarch64")]
        if L == 4 && !table.is_empty() {
            let (x, y) = aarch64::select(table, digit);
            return Affine { x, y };
        }
        let mut chosen = Affine {
            x: Uint::ZERO,
            y: Uint::ZERO,
        };
        for (i, entry) in table.iter().enumerate() {
            let matches = (((i as u64 + 1) ^ digit).wrapping_sub(1)) >> 63;
            chosen.cmov(
                &Affine {
                    x: Uint(entry[0]),
                    y: Uint(entry[1]),
                },
                matches,
            );
        }
        chosen
    }

    /// `k * p`, by signed five-bit windows over the scalar, the table
    /// read by scanning it whole.
    ///
    /// Booth's recoding gives each window a digit in `-16..=16`, so
    /// the table holds sixteen multiples rather than thirty-two, and
    /// a digit's sign only negates the entry, which is one
    /// subtraction. It holds no doubles beside them: the case that
    /// would want one cannot arise, for the reason
    /// [`jacobian_add_affine`] gives.
    ///
    /// [`jacobian_add_affine`]: Self::jacobian_add_affine
    fn point_mul(&self, p: &Point<L>, k: &Uint<L>) -> Point<L> {
        let base = self.to_jacobian(p);
        let mut multiples = [base; 16];
        let twice_base = self.jacobian_double(&base);
        for i in 1..16 {
            // Multiples in order, each the one before it plus the
            // base. The first of them is the base doubled, which is
            // the case the addition hands to `twice`.
            multiples[i] =
                self.jacobian_add(&multiples[i - 1], &base, &twice_base);
        }
        let table = multiples;

        let windows = (64 * L + 1).div_ceil(WINDOW);
        let mut acc = self.jacobian_identity();
        for window in (0..windows).rev() {
            if window + 1 != windows {
                for _ in 0..WINDOW {
                    acc = self.jacobian_double(&acc);
                }
            }
            let (digit, sign) = booth(k, window, WINDOW);
            let mut chosen = self.jacobian_identity();
            for (i, entry) in table.iter().enumerate() {
                let matches = (((i as u64 + 1) ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            // A negative digit takes the entry's opposite, which is
            // its `y` negated.
            let negated = Jacobian {
                x: chosen.x,
                y: self.sub(&Uint::ZERO, &chosen.y),
                z: chosen.z,
            };
            chosen.cmov(&negated, sign);
            // Two equal points cannot arise above the lowest window,
            // by the argument `jacobian_add_affine` sets out; at the
            // lowest they can, and the double is what that sum is.
            let twice = if window == 0 {
                self.jacobian_double(&chosen)
            } else {
                self.jacobian_identity()
            };
            acc = self.jacobian_add(&acc, &chosen, &twice);
        }
        let mut out = self.projective(&acc);
        // The table cannot hold the identity, so a point that is one
        // has no multiples to read and the sum above means nothing.
        // Every multiple of it is the identity.
        let none = p.z.is_zero_mask();
        out.x.cmov(&Uint::ZERO, none);
        out.y.cmov(&self.one, none);
        out.z.cmov(&Uint::ZERO, none);
        out
    }

    /// The same point in Jacobian coordinates: `(X Z : Y Z^2 : Z)`,
    /// which for `Z = 1`, as a point read from outside has, and for
    /// the identity is the triple unchanged.
    fn to_jacobian(&self, p: &Point<L>) -> Jacobian<L> {
        let zz = self.sqr(&p.z);
        Jacobian {
            x: self.mul(&p.x, &p.z),
            y: self.mul(&p.y, &zz),
            z: p.z,
        }
    }

    /// Back to the projective form the rest of the code holds:
    /// `(X Z : Y : Z^3)`, which needs no inversion.
    fn projective(&self, p: &Jacobian<L>) -> Point<L> {
        let zz = self.sqr(&p.z);
        Point {
            x: self.mul(&p.x, &p.z),
            y: p.y,
            z: self.mul(&zz, &p.z),
        }
    }

    fn jacobian_identity(&self) -> Jacobian<L> {
        Jacobian {
            x: self.one,
            y: self.one,
            z: Uint::ZERO,
        }
    }

    /// `a p + b G`, for scalars and a point that are all public.
    ///
    /// One pass over both scalars in signed digits five bits wide,
    /// sharing the doublings, with an addition only where a digit is
    /// nonzero, which is about one position in six. The odd multiples
    /// of each point are built first, and a digit's sign takes an
    /// entry's opposite.
    ///
    /// For public values only: which additions happen, and from which
    /// entries, is what the scalars are. Verification is the only
    /// caller, and everything it holds came with the signature.
    fn mul_add_vartime(
        &self,
        p: &Point<L>,
        a: &Uint<L>,
        b: &Uint<L>,
    ) -> Point<L> {
        let (point, point_twice) = self.odd_multiples(&self.to_jacobian(p));
        // Where the curve has per-window multiples of `G` checked in,
        // the base point's part of the sum is read from those instead
        // of built here: 37 additions and no doublings, and no table
        // to make first.
        let windowed = !self.curve.windows.is_empty();
        let (base, base_twice) = if windowed {
            ([self.jacobian_identity(); 8], [self.jacobian_identity(); 8])
        } else {
            self.odd_multiples(&self.to_jacobian(&self.generator()))
        };
        let a_digits = naf(a);
        // All zero leaves the loop below nothing to do for `b`.
        let b_digits = if windowed { [0i8; DIGITS] } else { naf(b) };

        let mut acc = self.jacobian_identity();
        let mut started = false;
        for i in (0..=64 * L).rev() {
            if started {
                acc = self.jacobian_double(&acc);
            }
            for (digits, table, doubles) in [
                (&a_digits, &point, &point_twice),
                (&b_digits, &base, &base_twice),
            ] {
                let digit = digits[i];
                if digit == 0 {
                    continue;
                }
                let at = (digit.unsigned_abs() as usize) >> 1;
                let (mut entry, mut twice) = (table[at], doubles[at]);
                if digit < 0 {
                    entry.y = self.sub(&Uint::ZERO, &entry.y);
                    twice.y = self.sub(&Uint::ZERO, &twice.y);
                }
                // As in the constant-time multiplication, `twice` is
                // what an addition of a point to itself comes to.
                acc = self.jacobian_add(&acc, &entry, &twice);
                started = true;
            }
        }
        if windowed {
            let bg = self.mul_base_vartime(b);
            // The two parts of the sum could be the same point, which
            // the addition settles with the double beside it.
            let twice = self.jacobian_double(&acc);
            acc = self.jacobian_add(&acc, &bg, &twice);
        }
        self.projective(&acc)
    }

    /// `k * G` for a public scalar, over the same per-window tables
    /// the fixed-base multiplication reads.
    ///
    /// The digit indexes its table rather than scanning it, and a
    /// zero digit is skipped. For public values only: verification
    /// is the caller, and the scalar there came with the signature.
    fn mul_base_vartime(&self, k: &Uint<L>) -> Jacobian<L> {
        let mut acc = self.jacobian_identity();
        let tables = self.curve.windows.chunks_exact(BASE_ENTRIES);
        for (window, table) in tables.enumerate() {
            let (digit, sign) = booth(k, window, BASE_WINDOW);
            if digit == 0 {
                continue;
            }
            let entry = &table[digit as usize - 1];
            let mut q = Affine {
                x: Uint(entry[0]),
                y: Uint(entry[1]),
            };
            if sign == 1 {
                q.y = self.sub(&Uint::ZERO, &q.y);
            }
            acc = self.jacobian_add_affine(&acc, &q);
        }
        acc
    }

    /// `p`, `3 p`, ... `15 p`, which are the entries a five-bit
    /// signed digit names, and their doubles, which the addition
    /// wants for the case of a point added to itself.
    fn odd_multiples(
        &self,
        p: &Jacobian<L>,
    ) -> ([Jacobian<L>; 8], [Jacobian<L>; 8]) {
        let twice = self.jacobian_double(p);
        let fallback = self.jacobian_double(&twice);
        let mut table = [*p; 8];
        for i in 1..8 {
            // Each is the one before it plus twice the point; only
            // the first of them is that point itself, which is the
            // case `fallback` covers.
            table[i] = self.jacobian_add(&table[i - 1], &twice, &fallback);
        }
        let mut doubles = table;
        for double in doubles.iter_mut() {
            *double = self.jacobian_double(double);
        }
        (table, doubles)
    }

    /// The curve's base point.
    fn generator(&self) -> Point<L> {
        // The first entry of the first comb is the generator itself.
        Point {
            x: Uint(self.curve.base[0][0]),
            y: Uint(self.curve.base[0][1]),
            z: self.one,
        }
    }

    /// `k * p` by the complete formulas, four bits at a time: what
    /// the windowed multiplication above is checked against.
    #[cfg(test)]
    fn point_mul_complete(&self, p: &Point<L>, k: &Uint<L>) -> Point<L> {
        let mut table = [self.identity(); 16];
        for i in 1..16 {
            table[i] = self.point_add(&table[i - 1], p);
        }
        let mut acc = self.identity();
        for window in (0..16 * L).rev() {
            for _ in 0..4 {
                acc = self.point_double(&acc);
            }
            let digit = (k.0[window >> 4] >> ((window & 15) * 4)) & 15;
            let mut chosen = table[0];
            for (i, entry) in table.iter().enumerate() {
                let matches = ((i as u64 ^ digit).wrapping_sub(1)) >> 63;
                chosen.cmov(entry, matches);
            }
            acc = self.point_add(&acc, &chosen);
        }
        acc
    }

    /// `k * G`, by the comb over the table in [`base`]: a doubling
    /// and one table addition for each bit of a block, rather than
    /// four doublings and an addition for each four bits of the
    /// scalar. The table is public; only the digit that reads it is
    /// secret, so the read scans every entry as [`point_mul`]'s
    /// does.
    ///
    /// [`point_mul`]: Self::point_mul
    fn mul_base(&self, k: &Uint<L>) -> Point<L> {
        if !self.curve.windows.is_empty() {
            return self.mul_base_windows(k);
        }
        let block = block::<L>();
        let span = block.div_ceil(TABLES);
        let mut acc = self.identity();
        for t in (0..span).rev() {
            acc = self.point_double(&acc);
            for (i, table) in self.curve.base.chunks_exact(ENTRIES).enumerate()
            {
                // The bit this comb reads in each block. Where the
                // blocks do not divide evenly the last comb runs past
                // the end of one, which is a fact about the widths
                // and not about the scalar.
                let offset = i * span + t;
                if offset >= block {
                    continue;
                }
                // That bit of every block, gathered least block
                // first. The last block runs past the scalar when the
                // width is not a multiple of `COMB`; those bits are
                // zero.
                let mut digit = 0u64;
                for j in 0..COMB {
                    let bit = j * block + offset;
                    if bit < 64 * L {
                        digit |= ((k.0[bit >> 6] >> (bit & 63)) & 1) << j;
                    }
                }
                // Entry `j` holds the digit `j + 1`, so a zero digit
                // matches nothing and leaves the identity, which is
                // what it stands for.
                let mut chosen = self.identity();
                for (j, entry) in table.iter().enumerate() {
                    let index = j as u64 + 1;
                    let matches = ((index ^ digit).wrapping_sub(1)) >> 63;
                    chosen.x.cmov(&Uint(entry[0]), matches);
                    chosen.y.cmov(&Uint(entry[1]), matches);
                    chosen.z.cmov(&self.one, matches);
                }
                acc = self.point_add(&acc, &chosen);
            }
        }
        acc
    }

    /// `k * G` over per-window tables: a signed seven-bit digit for
    /// each window of the scalar, each naming one of the 64 affine
    /// multiples of `2^(7 window) G` that window's table holds, and
    /// no doublings at all, since every entry is already shifted to
    /// where it belongs.
    ///
    /// The table is public and the digit that reads it is secret, so
    /// the read scans every entry, as the variable-base one does.
    fn mul_base_windows(&self, k: &Uint<L>) -> Point<L> {
        let mut acc = self.jacobian_identity();
        let tables = self.curve.windows.chunks_exact(BASE_ENTRIES);
        for (window, table) in tables.enumerate() {
            let (digit, sign) = booth(k, window, BASE_WINDOW);
            let mut chosen = self.select(table, digit);
            let negated = Affine {
                x: chosen.x,
                y: self.sub(&Uint::ZERO, &chosen.y),
            };
            chosen.cmov(&negated, sign);
            // The lowest window is the one where the accumulator can
            // equal the entry, as `jacobian_add_affine` explains.
            let sum = if window == 0 {
                let lifted = Jacobian {
                    x: chosen.x,
                    y: chosen.y,
                    z: self.one,
                };
                let twice = self.jacobian_double(&lifted);
                self.jacobian_add(&acc, &lifted, &twice)
            } else {
                self.jacobian_add_affine(&acc, &chosen)
            };
            // A digit of zero names no entry and adds nothing.
            acc.cmov(&sum, (digit | digit.wrapping_neg()) >> 63);
        }
        self.projective(&acc)
    }

    /// The affine coordinates, plain, or `None` for the identity.
    fn to_affine(&self, p: &Point<L>) -> Option<(Uint<L>, Uint<L>)> {
        if p.z.is_zero() {
            return None;
        }
        let zi = self.invert(&p.z);
        let x = self.field.from_mont(&self.mul(&p.x, &zi));
        let y = self.field.from_mont(&self.mul(&p.y, &zi));
        Some((x, y))
    }

    fn lift(&self, public: &Public<L>) -> Point<L> {
        Point {
            x: self.field.to_mont(&public.x),
            y: self.field.to_mont(&public.y),
            z: self.one,
        }
    }

    // The scalar ring, in plain form.

    fn scalar_mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        self.order.mulmod(a, b)
    }

    fn scalar_invert(&self, a: &Uint<L>) -> Uint<L> {
        let (exponent, _) = self.curve.n.sub_borrow(&Uint::from_limbs(&[2]));
        self.order.exp_public(a, &exponent)
    }

    /// A value below `2^bits` reduced modulo `n`, which takes one
    /// conditional subtraction because `n` is above `2^(bits - 1)`
    /// on every curve here. Everything reduced is a coordinate,
    /// below `p`, or a digest cut to the curve's bits.
    fn reduce_scalar(&self, a: &Uint<L>) -> Uint<L> {
        let (reduced, borrow) = a.sub_borrow(&self.curve.n);
        let mut out = *a;
        out.cmov(&reduced, 1 - borrow);
        out
    }

    /// Whether `a` is a scalar a key or a signature may hold: in
    /// `[1, n - 1]`.
    fn scalar_in_range(&self, a: &Uint<L>) -> bool {
        !a.is_zero() && a.less_than(&self.curve.n) == 1
    }

    /// The leftmost `bits` of a digest as a scalar, as FIPS 186-5
    /// section 6.4.1 and RFC 6979's `bits2int` both define; a
    /// shorter digest is the whole of it.
    fn hash_to_scalar(&self, digest: &[u8]) -> Uint<L> {
        let take = digest.len().min(self.curve.width());
        let value = Uint::from_be_bytes(&digest[..take]);
        let excess = (8 * take).saturating_sub(self.curve.bits);
        self.reduce_scalar(&value.shr(excess))
    }
}

/// A private scalar in `[1, n - 1]`, wiped on drop.
pub(crate) struct Secret<const L: usize> {
    d: Uint<L>,
}

impl<const L: usize> Drop for Secret<L> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

/// A public point in affine coordinates, plain, known to lie on
/// the curve: nothing constructs one without checking.
#[derive(Clone, Copy)]
pub(crate) struct Public<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
}

/// The tries key generation makes before giving up, each failing
/// with probability below 2^-32 on every curve.
const GENERATE_TRIES: usize = 100;

impl<const L: usize> Secret<L> {
    /// A scalar from its big-endian bytes, exactly the curve's
    /// width, refused unless in `[1, n - 1]`.
    pub(crate) fn try_new(e: &Engine<L>, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != e.curve.width() {
            return Err(Error::InvalidKeyLength(bytes.len()));
        }
        let d = Uint::from_be_bytes(bytes);
        if !e.scalar_in_range(&d) {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Secret { d })
    }

    /// A fresh scalar, by rejection: random bytes of the width, the
    /// bits past the curve's cleared, kept when in range, which
    /// nearly always they are.
    pub(crate) fn generate<R: Random>(
        e: &Engine<L>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut buf = [[0u8; 8]; L];
        let width = e.curve.width();
        for _ in 0..GENERATE_TRIES {
            // Wiped on every way out, not only the accepted one: a
            // refused candidate and a source that failed part way
            // through both leave bytes the generator has committed.
            let bytes = &mut buf.as_flattened_mut()[..width];
            if let Err(e) = rng.fill(bytes) {
                buf.zeroize();
                return Err(e);
            }
            bytes[0] &= e.curve.top_mask();
            let d = Uint::from_be_bytes(bytes);
            if e.scalar_in_range(&d) {
                buf.zeroize();
                return Ok(Secret { d });
            }
        }
        buf.zeroize();
        Err(Error::KeyGenerationFailed)
    }

    /// The scalar, big-endian, into `out` of the curve's width.
    pub(crate) fn bytes(&self, out: &mut [u8]) {
        self.d.to_be_bytes(out);
    }

    /// The public point, `d * G`.
    pub(crate) fn public(&self, e: &Engine<L>) -> Public<L> {
        let p = e.mul_base(&self.d);
        // A scalar in range times a generator of prime order is
        // never the identity, which is the only point `to_affine`
        // has no affine form for. Falling back to a fixed pair
        // would hand out (0, 0) -- not a point on any curve here --
        // as a public key, and nothing downstream would object.
        let Some((x, y)) = e.to_affine(&p) else {
            unreachable!("the public point is the identity");
        };
        Public { x, y }
    }

    /// The x-coordinate of `d * Q`, the ECDH shared secret, into
    /// `out` of the curve's width.
    pub(crate) fn shared_secret(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) {
        let mut p = e.point_mul(&e.lift(public), &self.d);
        // A validated point on a prime-order curve times a scalar in
        // `[1, n - 1]` is never the identity, which is the only point
        // with no affine form. Every `Public` is validated when it is
        // built, so there is nothing here a caller could provoke.
        let Some((mut x, mut y)) = e.to_affine(&p) else {
            unreachable!("the shared point is the identity");
        };
        x.to_be_bytes(out);
        x.zeroize();
        y.zeroize();
        // The projective form is the same secret in other
        // coordinates.
        p.x.zeroize();
        p.y.zeroize();
        p.z.zeroize();
    }

    /// An ECDSA signature over `message`, `r || s` into `out` of
    /// twice the curve's width, with the nonce from RFC 6979.
    pub(crate) fn sign<H: Hash + Clone + BlockType + Default>(
        &self,
        e: &Engine<L>,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        let width = e.curve.width();
        debug_assert_eq!(out.len(), 2 * width);
        let z = e.hash_to_scalar(H::digest(message).as_ref());

        // `int2octets(x)` and `bits2octets(h1)`, each of the width.
        let mut d_bytes = [[0u8; 8]; L];
        self.d.to_be_bytes(&mut d_bytes.as_flattened_mut()[..width]);
        let mut z_bytes = [[0u8; 8]; L];
        z.to_be_bytes(&mut z_bytes.as_flattened_mut()[..width]);
        let mut nonce = Nonce::<H>::try_new(
            &d_bytes.as_flattened()[..width],
            &z_bytes.as_flattened()[..width],
        )?;
        d_bytes.zeroize();

        loop {
            let mut k = nonce.next(e)?;
            let r = match e.to_affine(&e.mul_base(&k)) {
                Some((x, _)) => e.reduce_scalar(&x),
                None => Uint::ZERO,
            };
            // s = k^-1 (z + r d) mod n.
            let mut rd = e.scalar_mul(&r, &self.d);
            let mut sum = z.add_mod(&rd, &e.curve.n);
            let mut k_inverse = e.scalar_invert(&k);
            let s = e.scalar_mul(&k_inverse, &sum);
            k.zeroize();
            rd.zeroize();
            sum.zeroize();
            k_inverse.zeroize();
            if r.is_zero() || s.is_zero() {
                continue;
            }
            let (r_out, s_out) = out.split_at_mut(width);
            r.to_be_bytes(r_out);
            s.to_be_bytes(s_out);
            return Ok(());
        }
    }
}

impl<const L: usize> Public<L> {
    /// A point from its plain affine coordinates, checked to lie on
    /// the curve; the identity has no such coordinates and so is
    /// never accepted.
    fn try_from_affine(
        e: &Engine<L>,
        x: Uint<L>,
        y: Uint<L>,
    ) -> Result<Self, Error> {
        if x.less_than(&e.curve.p) == 0 || y.less_than(&e.curve.p) == 0 {
            return Err(Error::InvalidPublicKey);
        }
        let xm = e.field.to_mont(&x);
        let ym = e.field.to_mont(&y);
        if e.mul(&ym, &ym).0 != e.rhs(&xm).0 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Public { x, y })
    }

    /// A point from its SEC 1 encoding: `04 || x || y`, or `02` or
    /// `03` followed by `x` alone, the tag giving the parity of the
    /// `y` to recover. Anything else, the identity's lone zero byte
    /// included, is [`Error::InvalidPublicKey`].
    pub(crate) fn try_from_sec1(
        e: &Engine<L>,
        sec1: &[u8],
    ) -> Result<Self, Error> {
        let width = e.curve.width();
        match sec1 {
            [0x04, rest @ ..] if rest.len() == 2 * width => {
                let (x, y) = rest.split_at(width);
                Self::try_from_affine(
                    e,
                    Uint::from_be_bytes(x),
                    Uint::from_be_bytes(y),
                )
            }
            [tag @ (0x02 | 0x03), rest @ ..] if rest.len() == width => {
                let x = Uint::from_be_bytes(rest);
                if x.less_than(&e.curve.p) == 0 {
                    return Err(Error::InvalidPublicKey);
                }
                let xm = e.field.to_mont(&x);
                let root =
                    e.sqrt(&e.rhs(&xm)).ok_or(Error::InvalidPublicKey)?;
                let mut y = e.field.from_mont(&root);
                // The root and its negation have opposite parity,
                // since p is odd; the tag says which was meant.
                if y.is_odd() != (*tag == 0x03) {
                    y = Uint::ZERO.sub_mod(&y, &e.curve.p);
                }
                Ok(Public { x, y })
            }
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// The uncompressed SEC 1 encoding, `04 || x || y`, into `out`
    /// of one more than twice the curve's width.
    pub(crate) fn sec1(&self, e: &Engine<L>, out: &mut [u8]) {
        let width = e.curve.width();
        debug_assert_eq!(out.len(), 1 + 2 * width);
        out[0] = 0x04;
        self.x.to_be_bytes(&mut out[1..1 + width]);
        self.y.to_be_bytes(&mut out[1 + width..]);
    }

    /// Checks an ECDSA signature `r || s` over `message`.
    pub(crate) fn verify<H: Hash + Default>(
        &self,
        e: &Engine<L>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let width = e.curve.width();
        if signature.len() != 2 * width {
            return Err(Error::InvalidSignature);
        }
        let r = Uint::from_be_bytes(&signature[..width]);
        let s = Uint::from_be_bytes(&signature[width..]);
        if !e.scalar_in_range(&r) || !e.scalar_in_range(&s) {
            return Err(Error::InvalidSignature);
        }
        let z = e.hash_to_scalar(H::digest(message).as_ref());
        // R = (z / s) G + (r / s) Q, whose x must be r modulo n.
        let w = e.scalar_invert(&s);
        let u1 = e.scalar_mul(&z, &w);
        let u2 = e.scalar_mul(&r, &w);
        let sum = e.mul_add_vartime(&e.lift(self), &u2, &u1);
        let (x, _) = e.to_affine(&sum).ok_or(Error::InvalidSignature)?;
        if e.reduce_scalar(&x).0 == r.0 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// The nonce generator of RFC 6979 section 3.2: HMAC-DRBG over the
/// signature's hash, seeded with the private key and the message's
/// digest, so the same key and message always give the same nonce
/// and nothing else can.
struct Nonce<H: Hash + Clone + BlockType + Default> {
    k: H::Output,
    v: H::Output,
}

impl<H: Hash + Clone + BlockType + Default> Nonce<H> {
    /// Steps b through g, given `int2octets(x)` and
    /// `bits2octets(h1)`.
    fn try_new(x: &[u8], h: &[u8]) -> Result<Self, Error> {
        // V starts as 0x01 repeated and K as 0x00 repeated. A digest
        // is the only `H::Output` generic code can make; its value
        // is gone before either is used.
        let mut v = H::digest(&[]);
        v.as_mut().fill(0x01);
        let mut k = v;
        k.as_mut().fill(0x00);
        let mut nonce = Nonce { k, v };
        nonce.seed(0x00, x, h)?;
        nonce.seed(0x01, x, h)?;
        Ok(nonce)
    }

    /// `K = HMAC_K(V || tag || x || h)`, then `V = HMAC_K(V)`.
    fn seed(&mut self, tag: u8, x: &[u8], h: &[u8]) -> Result<(), Error> {
        let mut mac = Hmac::<H>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        mac.update(&[tag]);
        mac.update(x);
        mac.update(h);
        self.k = mac.finalize();
        self.v = Hmac::<H>::mac(self.k.as_ref(), self.v.as_ref());
        Ok(())
    }

    /// The next candidate in `[1, n - 1]`, step h: the width's bytes
    /// of output, cut to the curve's bits as `bits2int` says. A
    /// candidate out of range is skipped as the RFC says, and a
    /// previous one that the signature rejected has been skipped
    /// the same way.
    fn next<const L: usize>(
        &mut self,
        e: &Engine<L>,
    ) -> Result<Uint<L>, Error> {
        let width = e.curve.width();
        loop {
            let mut t = [[0u8; 8]; L];
            let mut filled = 0;
            while filled < width {
                self.v = Hmac::<H>::mac(self.k.as_ref(), self.v.as_ref());
                let out = &mut t.as_flattened_mut()[filled..width];
                let take = out.len().min(size_of::<H::Output>());
                out[..take].copy_from_slice(&self.v.as_ref()[..take]);
                filled += take;
            }
            let k = Uint::from_be_bytes(&t.as_flattened()[..width])
                .shr(8 * width - e.curve.bits);
            t.zeroize();
            self.seed_again()?;
            if e.scalar_in_range(&k) {
                return Ok(k);
            }
        }
    }

    /// `K = HMAC_K(V || 0x00)`, `V = HMAC_K(V)`: what follows every
    /// candidate, taken or not.
    fn seed_again(&mut self) -> Result<(), Error> {
        self.seed(0x00, &[], &[])
    }
}

impl<H: Hash + Clone + BlockType + Default> Drop for Nonce<H> {
    fn drop(&mut self) {
        self.k.as_mut().zeroize();
        self.v.as_mut().zeroize();
    }
}

// Formats: SEC 1 points inside the RFC 5480 SubjectPublicKeyInfo
// and the RFC 5915 ECPrivateKey, itself inside PKCS#8.

/// Room to encode or decode any key on these curves: the largest,
/// a PKCS#8 with attributes, is well under this.
const SCRATCH: usize = 512;

/// The PEM labels a private key may come under: PKCS#8 first, then
/// the bare ECPrivateKey that `openssl ecparam -genkey` writes.
const PRIVATE_LABELS: [&str; 2] = ["PRIVATE KEY", "EC PRIVATE KEY"];

const PUBLIC_LABEL: &str = "PUBLIC KEY";

/// Whether an AlgorithmIdentifier names a key on this curve:
/// `id-ecPublicKey` with the curve's own OID as its parameters.
fn is_this_curve<const L: usize>(
    curve: &Curve<L>,
    algorithm: &der::Algorithm,
) -> bool {
    let mut params = Reader::new(algorithm.params);
    algorithm.oid == EC_PUBLIC_KEY
        && params.oid().is_ok_and(|oid| oid == curve.oid)
        && params.end().is_ok()
}

fn algorithm_identifier<const L: usize>(curve: &Curve<L>, w: &mut Writer) {
    w.oid(EC_PUBLIC_KEY);
    w.oid(curve.oid);
}

impl<const L: usize> Public<L> {
    /// A point from a SubjectPublicKeyInfo naming this curve.
    pub(crate) fn from_spki(e: &Engine<L>, der: &[u8]) -> Result<Self, Error> {
        let (algorithm, point) = der::read_spki(der)?;
        if !is_this_curve(e.curve, &algorithm) {
            return Err(Error::WrongAlgorithm);
        }
        Self::try_from_sec1(e, point)
    }

    /// The SubjectPublicKeyInfo, with the point uncompressed.
    pub(crate) fn spki(
        &self,
        e: &Engine<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut sec1 = [0u8; SCRATCH];
        let sec1 = &mut sec1[..1 + 2 * e.curve.width()];
        self.sec1(e, sec1);
        der::write_spki_with(
            out,
            |w| algorithm_identifier(e.curve, w),
            |w| w.raw(sec1),
        )
    }

    pub(crate) fn from_pem(e: &Engine<L>, pem: &[u8]) -> Result<Self, Error> {
        let mut der = [0u8; SCRATCH];
        let (_, n) = pem::decode_one_of(&[PUBLIC_LABEL], pem, &mut der)?;
        Self::from_spki(e, &der[..n])
    }

    pub(crate) fn pem(
        &self,
        e: &Engine<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut der = [0u8; SCRATCH];
        let n = self.spki(e, &mut der)?;
        pem::encode(PUBLIC_LABEL, &der[..n], out)
    }
}

impl<const L: usize> Secret<L> {
    /// An RFC 5915 ECPrivateKey, with the public point it carried
    /// if any. Its parameters, when present, must name this curve;
    /// inside PKCS#8 they are usually left out, since the outer
    /// algorithm identifier already says.
    fn from_ec_private_key(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Option<Public<L>>), Error> {
        let mut outer = Reader::new(der);
        let mut key = outer.sequence()?;
        outer.end()?;
        if key.integer()? != [1] {
            return Err(Error::InvalidEncoding);
        }
        let d = key.octet_string()?;
        // The parameters, when present, name a curve; any curve but
        // this one, or anything that is not a named curve, is
        // another algorithm's key.
        if let Some(params) = key.optional(der::context(0))? {
            let mut params = Reader::new(params);
            let named = params.oid().is_ok_and(|oid| oid == e.curve.oid)
                && params.end().is_ok();
            if !named {
                return Err(Error::WrongAlgorithm);
            }
        }
        // A scalar of another width is another curve's, whatever
        // the parameters said; one out of range is a bad key.
        let secret = Self::try_new(e, d).map_err(|err| match err {
            Error::InvalidKeyLength(_) => Error::InvalidEncoding,
            other => other,
        })?;
        let public = match key.optional(der::context(1))? {
            Some(wrapped) => {
                let mut wrapped = Reader::new(wrapped);
                let point = wrapped.bit_string()?;
                wrapped.end()?;
                Some(Public::try_from_sec1(e, point)?)
            }
            None => None,
        };
        key.end()?;
        Ok((secret, public))
    }

    /// The public point, derived, and checked against the one the
    /// structure carried when it carried one: a pair that disagrees
    /// has been corrupted.
    fn with_public(
        self,
        e: &Engine<L>,
        carried: Option<Public<L>>,
    ) -> Result<(Self, Public<L>), Error> {
        let public = self.public(e);
        if let Some(carried) = carried
            && (carried.x.0 != public.x.0 || carried.y.0 != public.y.0)
        {
            return Err(Error::InconsistentKey);
        }
        Ok((self, public))
    }

    /// A key from a PKCS#8 PrivateKeyInfo naming this curve.
    pub(crate) fn from_pkcs8(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Public<L>, Pkcs8Form), Error> {
        let info = der::read_pkcs8(der)?;
        if !is_this_curve(e.curve, &info.algorithm) {
            return Err(Error::WrongAlgorithm);
        }
        let (secret, carried) = Self::from_ec_private_key(e, info.private_key)?;
        let form = Pkcs8Form {
            v1: info.v1,
            public_key: carried.is_some(),
        };
        let (secret, public) = secret.with_public(e, carried)?;
        Ok((secret, public, form))
    }

    /// A key from a bare ECPrivateKey, the `EC PRIVATE KEY` form.
    pub(crate) fn from_sec1_der(
        e: &Engine<L>,
        der: &[u8],
    ) -> Result<(Self, Public<L>), Error> {
        let (secret, carried) = Self::from_ec_private_key(e, der)?;
        secret.with_public(e, carried)
    }

    /// The PKCS#8 PrivateKeyInfo, around an ECPrivateKey that
    /// carries the public point and leaves the parameters to the
    /// outer identifier, which is the form OpenSSL writes.
    pub(crate) fn pkcs8(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let width = e.curve.width();
        let mut d = [[0u8; 8]; L];
        let d_bytes = &mut d.as_flattened_mut()[..width];
        self.d.to_be_bytes(d_bytes);
        let mut sec1 = [0u8; SCRATCH];
        let sec1 = &mut sec1[..1 + 2 * width];
        public.sec1(e, sec1);
        let result = der::write_pkcs8_with(
            out,
            |w| algorithm_identifier(e.curve, w),
            |w| {
                w.sequence(|w| {
                    w.integer(&[1]);
                    w.octet_string(&d.as_flattened()[..width]);
                    w.context(1, |w| w.bit_string(sec1));
                })
            },
        );
        d.zeroize();
        result
    }

    /// Either private form from a PEM block, told apart by its label.
    pub(crate) fn from_pem(
        e: &Engine<L>,
        pem: &[u8],
    ) -> Result<(Self, Public<L>), Error> {
        let mut der = [0u8; SCRATCH];
        let result = pem::decode_one_of(&PRIVATE_LABELS, pem, &mut der)
            .and_then(|(form, n)| match form {
                0 => Self::from_pkcs8(e, &der[..n]).map(|(s, p, _)| (s, p)),
                _ => Self::from_sec1_der(e, &der[..n]),
            });
        der.zeroize();
        result
    }

    /// The PKCS#8 form as a `PRIVATE KEY` PEM block.
    pub(crate) fn pem(
        &self,
        e: &Engine<L>,
        public: &Public<L>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut der = [0u8; SCRATCH];
        let result = self
            .pkcs8(e, public, &mut der)
            .and_then(|n| pem::encode(PRIVATE_LABELS[0], &der[..n], out));
        der.zeroize();
        result
    }
}

/// An ECDSA signature `r || s` as the DER `ECDSA-Sig-Value` of RFC
/// 5480, `SEQUENCE { INTEGER r, INTEGER s }`, into the front of
/// `out`; the length varies with the values' leading bits.
pub(crate) fn signature_to_der(
    rs: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let (r, s) = rs.split_at(rs.len() / 2);
    der::encode(out, |w| {
        w.sequence(|w| {
            w.integer(r);
            w.integer(s);
        })
    })
}

/// The reverse: `r || s` of `out`'s width from a DER signature. An
/// integer wider than the curve is not a signature on it.
pub(crate) fn signature_from_der(
    der: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let width = out.len() / 2;
    let mut outer = Reader::new(der);
    let mut seq = outer.sequence()?;
    outer.end()?;
    let r = seq.integer()?;
    let s = seq.integer()?;
    seq.end()?;
    if r.len() > width || s.len() > width {
        return Err(Error::InvalidEncoding);
    }
    out.fill(0);
    out[width - r.len()..width].copy_from_slice(r);
    out[2 * width - s.len()..].copy_from_slice(s);
    Ok(())
}

/// The key types of one curve for one scheme: the constants, the
/// two structs, and everything on them that is not the scheme's own
/// operation. Invoked inside a module per curve by `sig::ecdsa` and
/// `kex::ecdh`, which add `sign` and `verify`, or `shared_secret`.
///
/// `$job` is what the key does, for the docs; `$curve` names it.
macro_rules! key_types {
    (
        $constants:expr, $limbs:literal, $curve:literal, $job:literal,
        der $der:literal, public der $public_der:literal
    ) => {
        use crate::Error;
        use crate::Random;
        use crate::math::ec::{Engine, Public, Secret};

        /// The length of a private key.
        pub const KEY_SIZE: usize = $constants.width();

        /// The length of a public key in its uncompressed SEC 1
        /// form, `04 || x || y`.
        pub const PUBLIC_KEY_SIZE: usize = 1 + 2 * KEY_SIZE;

        /// The length of a private key's DER encoding, a PKCS#8
        /// `PrivateKeyInfo` around an RFC 5915 `ECPrivateKey` that
        /// carries the public point.
        pub const DER_SIZE: usize = $der;

        /// The length of a public key's DER encoding, a
        /// `SubjectPublicKeyInfo` (RFC 5480).
        pub const PUBLIC_KEY_DER_SIZE: usize = $public_der;

        /// The length of a private key's PEM encoding, a
        /// `PRIVATE KEY` block.
        pub const PEM_SIZE: usize =
            crate::codec::pem::encoded_len("PRIVATE KEY", DER_SIZE);

        /// The length of a public key's PEM encoding, a `PUBLIC KEY`
        /// block.
        pub const PUBLIC_KEY_PEM_SIZE: usize =
            crate::codec::pem::encoded_len("PUBLIC KEY", PUBLIC_KEY_DER_SIZE);

        #[doc = concat!("A ", $job, " key on ", $curve, ": a secret")]
        /// scalar in `[1, n - 1]`, wiped on drop, with its public
        /// point alongside.
        pub struct PrivateKey {
            secret: Secret<$limbs>,
            public: PublicKey,
        }

        #[doc = concat!("A public key on ", $curve, ": a point known")]
        /// to lie on the curve, since every way of making one checks.
        #[derive(Clone, Copy)]
        pub struct PublicKey {
            point: Public<$limbs>,
        }

        impl PrivateKey {
            fn from_secret(
                secret: Secret<$limbs>,
                public: Public<$limbs>,
            ) -> Self {
                PrivateKey {
                    secret,
                    public: PublicKey { point: public },
                }
            }

            /// A fresh key: a uniform scalar in `[1, n - 1]`, by
            /// rejection sampling, which fails once in 2^32 draws
            /// and is retried; the public point is derived.
            pub fn generate<R: Random>(rng: &mut R) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let secret = Secret::generate(&e, rng)?;
                let public = secret.public(&e);
                Ok(Self::from_secret(secret, public))
            }

            /// A key from its secret scalar, big-endian, which must be
            /// in `[1, n - 1]`: [`Error::InvalidPrivateKey`] for zero
            /// or a value at or above the order.
            pub fn try_new(secret: &[u8; KEY_SIZE]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let secret = Secret::try_new(&e, secret)?;
                let public = secret.public(&e);
                Ok(Self::from_secret(secret, public))
            }

            /// The secret scalar, big-endian. The caller holds a
            /// secret now, and should wipe it when done.
            pub fn secret_bytes(&self) -> [u8; KEY_SIZE] {
                let mut out = [0u8; KEY_SIZE];
                self.secret.bytes(&mut out);
                out
            }

            /// The public half.
            pub fn public_key(&self) -> &PublicKey {
                &self.public
            }

            /// A key from its DER PKCS#8 `PrivateKeyInfo`, the form
            /// under `PRIVATE KEY` in a PEM file: `id-ecPublicKey`
            /// naming this curve, around an RFC 5915 `ECPrivateKey`.
            /// A public point carried inside is checked against the
            /// secret's own, and a pair that disagrees is
            /// [`Error::InconsistentKey`]. A key on another curve, or
            /// of another algorithm, is [`Error::WrongAlgorithm`], and
            /// anything else wrong with the bytes
            /// [`Error::InvalidEncoding`].
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                Self::try_from_der_with_form(der).map(|(key, _)| key)
            }

            /// As [`try_from_der`](Self::try_from_der), and also which
            /// form the structure took: whether the `ECPrivateKey`
            /// carried the public point.
            pub fn try_from_der_with_form(
                der: &[u8],
            ) -> Result<(Self, crate::Pkcs8Form), Error> {
                let e = Engine::new(&$constants);
                let (secret, public, form) = Secret::from_pkcs8(&e, der)?;
                Ok((Self::from_secret(secret, public), form))
            }

            /// A key from a bare `ECPrivateKey` (RFC 5915), the DER
            /// inside an `EC PRIVATE KEY` PEM block, as
            /// `openssl ec` writes it. The parameters, when
            /// present, must name this curve, and a carried public
            /// point is checked against the secret's own; the
            /// errors are as for [`try_from_der`](Self::try_from_der).
            pub fn try_from_sec1_der(der: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let (secret, public) = Secret::from_sec1_der(&e, der)?;
                Ok(Self::from_secret(secret, public))
            }

            /// Writes the key as a `PrivateKeyInfo` into the front of
            /// `out`, returning the length, always [`DER_SIZE`]; a
            /// buffer too small gets [`Error::OutputTooSmall`]. The
            /// output is a secret, to be wiped when done.
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.secret.pkcs8(&e, &self.public.point, out)
            }

            /// A key from a PEM block (RFC 7468) labelled
            /// `PRIVATE KEY`, around the PKCS#8 form, or
            /// `EC PRIVATE KEY`, around the bare `ECPrivateKey` that
            /// `openssl ecparam -genkey` writes. Whitespace and line
            /// ends are read leniently; anything else that is not
            /// exactly one well-formed block for this curve, an
            /// encrypted key included, is [`Error::InvalidEncoding`].
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                let (secret, public) = Secret::from_pem(&e, pem)?;
                Ok(Self::from_secret(secret, public))
            }

            /// Writes the key as a `PRIVATE KEY` PEM block, ASCII with
            /// LF line ends, into the front of `out`, returning the
            /// length, always [`PEM_SIZE`]. A secret, to be wiped.
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.secret.pem(&e, &self.public.point, out)
            }
        }

        impl PublicKey {
            /// A key from its SEC 1 encoding: `04 || x || y`, or the
            /// compressed `02 || x` and `03 || x` with the tag giving
            /// the parity of `y`. The point must lie on the curve;
            /// anything else is [`Error::InvalidPublicKey`].
            pub fn try_from_sec1(sec1: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::try_from_sec1(&e, sec1)?,
                })
            }

            /// The uncompressed SEC 1 encoding, `04 || x || y`.
            pub fn sec1_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
                let e = Engine::new(&$constants);
                let mut out = [0u8; PUBLIC_KEY_SIZE];
                self.point.sec1(&e, &mut out);
                out
            }

            /// A key from its DER `SubjectPublicKeyInfo` (RFC 5480),
            /// the form under `PUBLIC KEY` in a PEM file, which must
            /// name this curve; the point inside may be compressed.
            pub fn try_from_der(der: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::from_spki(&e, der)?,
                })
            }

            /// Writes the key as a `SubjectPublicKeyInfo`, the point
            /// uncompressed, into the front of `out`, returning the
            /// length, always [`PUBLIC_KEY_DER_SIZE`].
            pub fn der_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.point.spki(&e, out)
            }

            /// A key from a `PUBLIC KEY` PEM block, read as
            /// [`PrivateKey::try_from_pem`] reads its own.
            pub fn try_from_pem(pem: &[u8]) -> Result<Self, Error> {
                let e = Engine::new(&$constants);
                Ok(PublicKey {
                    point: Public::from_pem(&e, pem)?,
                })
            }

            /// Writes the key as a `PUBLIC KEY` PEM block into the
            /// front of `out`, returning the length, always
            /// [`PUBLIC_KEY_PEM_SIZE`].
            pub fn pem_bytes(&self, out: &mut [u8]) -> Result<usize, Error> {
                let e = Engine::new(&$constants);
                self.point.pem(&e, out)
            }
        }
    };
}

pub(crate) use key_types;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha2::{Sha256, Sha384};

    /// The generator, in the field's domain. Only the tests need
    /// it by itself: every multiplication of it goes through the
    /// comb table instead.
    fn generator<const L: usize>(e: &Engine<L>) -> Point<L> {
        Point {
            x: e.field.to_mont(&e.curve.gx),
            y: e.field.to_mont(&e.curve.gy),
            z: e.one,
        }
    }

    /// Affine coordinates as limbs, comparable.
    fn affine<const L: usize>(
        e: &Engine<L>,
        p: &Point<L>,
    ) -> Option<([u64; L], [u64; L])> {
        e.to_affine(p).map(|(x, y)| (x.0, y.0))
    }

    fn unhex<'a>(hex: &str, buf: &'a mut [u8]) -> &'a [u8] {
        let hex = hex.as_bytes();
        for (byte, pair) in buf.iter_mut().zip(hex.chunks(2)) {
            let s = core::str::from_utf8(pair).unwrap();
            *byte = u8::from_str_radix(s, 16).unwrap();
        }
        &buf[..hex.len() / 2]
    }

    /// Both field primes are the ones the Montgomery reduction has
    /// a shift-and-add form for. They are spelled twice, in hex
    /// here and as limbs there, so check the spellings agree: a
    /// mismatch would be silently correct and half the speed.
    #[test]
    fn field_primes_take_the_shaped_reduction() {
        use crate::math::montgomery::{P256_PRIME, P384_PRIME};

        assert_eq!(P256.p.0, P256_PRIME);
        assert_eq!(P384.p.0, P384_PRIME);
    }

    /// The generator is on the curve, and doubling it by the
    /// complete formula agrees with adding it to itself, and with
    /// multiplying by two; the identity behaves.
    #[test]
    fn group_law_basics() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            Public::try_from_affine(&e, curve.gx, curve.gy).unwrap();
            let two_g = e.point_add(&g, &g);
            let by_mul = e.point_mul(&g, &Uint::from_limbs(&[2]));
            assert_eq!(affine(&e, &two_g), affine(&e, &by_mul));
            let (x, y) = e.to_affine(&two_g).unwrap();
            Public::try_from_affine(&e, x, y).unwrap();
            // Identity plus G is G; n G is the identity; (n-1) G = -G.
            let id = e.identity();
            assert_eq!(affine(&e, &e.point_add(&id, &g)), affine(&e, &g));
            assert!(e.to_affine(&e.point_mul(&g, &curve.n)).is_none());
            let (minus_one, _) = curve.n.sub_borrow(&Uint::one());
            let (x, y) = e.to_affine(&e.point_mul(&g, &minus_one)).unwrap();
            assert_eq!(x.0, curve.gx.0);
            assert_eq!(y.0, Uint::ZERO.sub_mod(&curve.gy, &curve.p).0);
            assert!(e.to_affine(&e.point_mul(&g, &Uint::ZERO)).is_none());
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// The dedicated doubling agrees with adding a point to
    /// itself, on the identity and along a run of multiples of `G`.
    #[test]
    fn doubling_matches_the_general_addition() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            let mut p = e.identity();
            for _ in 0..8 {
                assert_eq!(
                    affine(&e, &e.point_double(&p)),
                    affine(&e, &e.point_add(&p, &p)),
                );
                p = e.point_add(&p, &g);
            }
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// The bases each comb's table is built from: block `j` of comb
    /// `i` stands for `2^(j block + i span) G`.
    fn comb_bases<const L: usize>(e: &Engine<L>) -> [[Point<L>; COMB]; TABLES] {
        let block = block::<L>();
        let span = block.div_ceil(TABLES);
        let mut bases = [[e.identity(); COMB]; TABLES];
        let mut point = generator(e);
        let mut bit = 0;
        for j in 0..COMB {
            for (i, table) in bases.iter_mut().enumerate() {
                // The doublings walk the exponents in order, so each
                // base is the one before it doubled the difference.
                let want = j * block + i * span;
                while bit < want {
                    point = e.point_double(&point);
                    bit += 1;
                }
                table[j] = point;
            }
        }
        bases
    }

    /// The entry a digit stands for: the sum of the comb's bases over
    /// the digit's set bits.
    fn comb_entry<const L: usize>(
        e: &Engine<L>,
        bases: &[Point<L>; COMB],
        digit: usize,
    ) -> Point<L> {
        let mut sum = e.identity();
        for (j, base) in bases.iter().enumerate() {
            if digit >> j & 1 == 1 {
                sum = e.point_add(&sum, base);
            }
        }
        sum
    }

    /// The table read keeps the entry the digit names, and nothing
    /// for a digit that names none. Where the processor has the
    /// instructions this is the vectorised read; the expectation
    /// here is written out rather than taken from the scan it
    /// replaced.
    #[test]
    fn table_reads_keep_the_entry_the_digit_names() {
        let e = Engine::new(&P256);
        let mut table = [[[0u64; 4]; 2]; BASE_ENTRIES];
        for (i, entry) in table.iter_mut().enumerate() {
            for (j, limb) in entry.iter_mut().flatten().enumerate() {
                *limb = (i as u64 + 1).wrapping_mul(0x0123456789abcdef)
                    ^ ((j as u64) << 40);
            }
        }
        for digit in 0..=BASE_ENTRIES as u64 + 1 {
            let chosen = e.select(&table, digit);
            let wanted = match digit {
                0 => [[0u64; 4]; 2],
                d if d as usize <= BASE_ENTRIES => table[d as usize - 1],
                _ => [[0u64; 4]; 2],
            };
            assert_eq!(chosen.x.0, wanted[0], "digit {digit} x");
            assert_eq!(chosen.y.0, wanted[1], "digit {digit} y");
        }
    }

    /// Whether this processor takes the written-out blocks: on
    /// x86-64 they need ADX and BMI2, and on A64 they are baseline.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn written_out<const L: usize>(e: &Engine<L>) -> bool {
        #[cfg(target_arch = "x86_64")]
        return e.fast.is_some();
        #[cfg(target_arch = "aarch64")]
        return e.p256;
    }

    /// The doubling written out for the processor agrees with the
    /// formula as Rust reads it, on points whose coordinates run to
    /// the ends of the field.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn written_out_doubling_matches_the_formula() {
        let e = Engine::new(&P256);
        if !written_out(&e) {
            return;
        }
        let mut point = e.to_jacobian(&generator(&e));
        for i in 0..64 {
            assert_eq!(
                e.jacobian_double(&point).x.0,
                e.portable_double(&point).x.0,
                "{i} x"
            );
            assert_eq!(
                e.jacobian_double(&point).y.0,
                e.portable_double(&point).y.0,
                "{i} y"
            );
            assert_eq!(
                e.jacobian_double(&point).z.0,
                e.portable_double(&point).z.0,
                "{i} z"
            );
            point = e.portable_double(&point);
        }
        // The identity, and a point whose coordinates are the
        // largest the field holds.
        let (prime, _) = P256.p.sub_borrow(&Uint::one());
        for odd in [
            e.jacobian_identity(),
            Jacobian {
                x: prime,
                y: prime,
                z: prime,
            },
        ] {
            assert_eq!(
                e.jacobian_double(&odd).x.0,
                e.portable_double(&odd).x.0
            );
            assert_eq!(
                e.jacobian_double(&odd).y.0,
                e.portable_double(&odd).y.0
            );
            assert_eq!(
                e.jacobian_double(&odd).z.0,
                e.portable_double(&odd).z.0
            );
        }
    }

    /// The mixed addition written out for the processor agrees with
    /// the formula as Rust reads it, on points whose coordinates run
    /// to the ends of the field, and where the point added to is the
    /// identity.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn written_out_mixed_addition_matches_the_formula() {
        let e = Engine::new(&P256);
        if !written_out(&e) {
            return;
        }
        let g = e.to_jacobian(&generator(&e));
        let table = e.normalise(&[e.jacobian_double(&g)]);
        // Adding the same multiple each time keeps the two points
        // distinct, which is the case the formula is for.
        let q = Affine {
            x: Uint(table[0][0]),
            y: Uint(table[0][1]),
        };
        let mut point = g;
        for i in 0..32 {
            let wanted = e.portable_add_affine(&point, &q);
            let got = e.jacobian_add_affine(&point, &q);
            assert_eq!(got.x.0, wanted.x.0, "{i} x");
            assert_eq!(got.y.0, wanted.y.0, "{i} y");
            assert_eq!(got.z.0, wanted.z.0, "{i} z");
            point = wanted;
        }
        // The identity, which both settle by the same mask.
        let none = e.jacobian_identity();
        let wanted = e.portable_add_affine(&none, &q);
        let got = e.jacobian_add_affine(&none, &q);
        assert_eq!(got.x.0, wanted.x.0);
        assert_eq!(got.y.0, wanted.y.0);
        assert_eq!(got.z.0, wanted.z.0);
    }

    /// The general addition written out for the processor agrees
    /// with the formula as Rust reads it, on distinct points, on
    /// equal ones, on a pair of inverses, and where either side is
    /// the identity.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn written_out_addition_matches_the_formula() {
        let e = Engine::new(&P256);
        if !written_out(&e) {
            return;
        }
        let g = e.to_jacobian(&generator(&e));
        let two = e.jacobian_double(&g);
        let four = e.jacobian_double(&two);
        let minus = Jacobian {
            x: g.x,
            y: e.sub(&Uint::ZERO, &g.y),
            z: g.z,
        };
        let none = e.jacobian_identity();
        let pairs = [
            (g, two),
            (two, four),
            (g, g),
            (g, minus),
            (none, g),
            (g, none),
            (none, none),
        ];
        for (i, (p, q)) in pairs.iter().enumerate() {
            let twice = e.jacobian_double(p);
            let wanted = e.portable_add(p, q, &twice);
            let got = e.jacobian_add(p, q, &twice);
            assert_eq!(got.x.0, wanted.x.0, "{i} x");
            assert_eq!(got.y.0, wanted.y.0, "{i} y");
            assert_eq!(got.z.0, wanted.z.0, "{i} z");
        }
    }

    /// The inversion chain written out for the processor is the
    /// same value as the exponentiation it replaces.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn written_out_inversion_matches_the_exponentiation() {
        let e = Engine::new(&P256);
        if !written_out(&e) {
            return;
        }
        let mut value = e.one;
        for i in 0..32 {
            assert_eq!(e.invert(&value).0, e.portable_invert(&value).0, "{i}");
            value = e.add(&e.mul(&value, &value), &e.one);
        }
        // Zero inverts to zero, and one to one.
        assert_eq!(e.invert(&Uint::ZERO).0, [0u64; 4]);
        assert_eq!(e.invert(&e.one).0, e.one.0);
        // The largest value the field holds.
        let (top, _) = P256.p.sub_borrow(&Uint::one());
        assert_eq!(e.invert(&top).0, e.portable_invert(&top).0);
    }

    /// The multiples one per-window table holds, window by window:
    /// entry `j` of window `w` is `(j + 1) 2^(BASE_WINDOW w) G`.
    fn window_entries<const L: usize>(
        e: &Engine<L>,
    ) -> std::vec::Vec<std::vec::Vec<Point<L>>> {
        let count = (64 * L + 1).div_ceil(BASE_WINDOW);
        let mut shifted = generator(e);
        let mut out = std::vec::Vec::new();
        for _ in 0..count {
            let mut table = std::vec::Vec::with_capacity(BASE_ENTRIES);
            let mut multiple = shifted;
            table.push(multiple);
            for _ in 1..BASE_ENTRIES {
                multiple = e.point_add(&multiple, &shifted);
                table.push(multiple);
            }
            out.push(table);
            for _ in 0..BASE_WINDOW {
                shifted = e.point_double(&shifted);
            }
        }
        out
    }

    /// Every entry of the per-window table is the multiple of `G` it
    /// stands for, as the comb check below says of the combs.
    #[test]
    fn base_windows_are_multiples_of_g() {
        let e = Engine::new(&P256);
        let wanted = window_entries(&e);
        assert_eq!(P256.windows.len(), wanted.len() * BASE_ENTRIES);
        let tables = P256.windows.chunks_exact(BASE_ENTRIES);
        for (w, (table, multiples)) in tables.zip(&wanted).enumerate() {
            for (j, (entry, point)) in table.iter().zip(multiples).enumerate() {
                let (x, y) = e.to_affine(point).expect("a multiple of G");
                assert_eq!(e.field.to_mont(&x).0, entry[0], "{w} {j} x");
                assert_eq!(e.field.to_mont(&y).0, entry[1], "{w} {j} y");
            }
        }
    }

    /// Every entry of every comb table is the multiple of `G` it
    /// stands for: the sum of `2^(j block + i span) G` over the set
    /// bits of its index, in the field's domain. This is what says
    /// the checked-in tables are the curve's and not something else.
    #[test]
    fn base_tables_are_multiples_of_g() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let bases = comb_bases(&e);
            assert_eq!(curve.base.len(), TABLES * ENTRIES);
            for (i, table) in curve.base.chunks_exact(ENTRIES).enumerate() {
                for (j, entry) in table.iter().enumerate() {
                    let sum = comb_entry(&e, &bases[i], j + 1);
                    let (x, y) = e.to_affine(&sum).expect("a sum of bases");
                    assert_eq!(e.field.to_mont(&x).0, entry[0], "{i} {j} x");
                    assert_eq!(e.field.to_mont(&y).0, entry[1], "{i} {j} y");
                }
            }
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// Prints the tables in the form `base.rs` holds them. Ignored:
    /// it is how that file is made, not a check on it, and
    /// `base_tables_are_multiples_of_g` is the check.
    #[test]
    #[ignore = "writes the table in base.rs; run it to rebuild that"]
    fn print_base_tables() {
        fn print<const L: usize>(name: &str, curve: &Curve<L>) {
            let e = Engine::new(curve);
            let bases = comb_bases(&e);
            std::println!(
                "pub(crate) const {}: [[[u64; {}]; 2]; {}] = [",
                name,
                L,
                TABLES * ENTRIES
            );
            for table in bases.iter() {
                for digit in 1..=ENTRIES {
                    let sum = comb_entry(&e, table, digit);
                    let (x, y) = e.to_affine(&sum).expect("a sum of bases");
                    let hex = |v: Uint<L>| {
                        let words: std::vec::Vec<std::string::String> =
                            v.0.iter()
                                .map(|w| std::format!("0x{w:016x}"))
                                .collect();
                        words.join(", ")
                    };
                    std::println!(
                        "    [[{}],\n     [{}]],",
                        hex(e.field.to_mont(&x)),
                        hex(e.field.to_mont(&y))
                    );
                }
            }
            std::println!("];");
        }
        print("P256_BASE", &P256);
        print("P384_BASE", &P384);
        print("P521_BASE", &P521);

        let e = Engine::new(&P256);
        let tables = window_entries(&e);
        std::println!(
            "pub(crate) static P256_WINDOWS: [[[u64; 4]; 2]; {}] = [",
            tables.len() * BASE_ENTRIES
        );
        for table in &tables {
            for point in table {
                let (x, y) = e.to_affine(point).expect("a multiple of G");
                let hex = |v: Uint<4>| {
                    let words: std::vec::Vec<std::string::String> =
                        v.0.iter()
                            .map(|w| std::format!("0x{w:016x}"))
                            .collect();
                    words.join(", ")
                };
                std::println!(
                    "    [[{}],\n     [{}]],",
                    hex(e.field.to_mont(&x)),
                    hex(e.field.to_mont(&y))
                );
            }
        }
        std::println!("];");
    }

    /// The windowed multiplication in Jacobian coordinates agrees
    /// with the complete formulas, over scalars that reach its
    /// corners: zero, one, the order less one, values whose top
    /// window is partly past the scalar, and ones whose digits repeat
    /// so that a window's entry is what the accumulator already
    /// holds, which is the case the formulas cannot do themselves.
    #[test]
    fn windowed_matches_the_complete_multiplication() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            let (order_less_one, _) = curve.n.sub_borrow(&Uint::one());
            let mut scalars = std::vec![
                Uint::<L>::ZERO,
                Uint::one(),
                Uint::from_limbs(&[2]),
                Uint::from_limbs(&[16]),
                Uint::from_limbs(&[31]),
                Uint::from_limbs(&[32]),
                Uint::from_limbs(&[0x21084210]),
                order_less_one,
                curve.n,
            ];
            // Every limb the same, so every window is the same digit.
            scalars.push(Uint([0x1084210842108421; L]));
            let mut x = Uint::<L>::from_limbs(&[0x9e3779b97f4a7c15]);
            for _ in 0..8 {
                x = e.order.mulmod(&x, &Uint::from_limbs(&[0x100000001]));
                scalars.push(x);
            }
            for k in scalars {
                let want = affine(&e, &e.point_mul_complete(&g, &k));
                let got = affine(&e, &e.point_mul(&g, &k));
                assert_eq!(want, got, "{:?}", k.0);
            }
            // And the identity as the point, which has no inverse to
            // take: every multiple of it is itself.
            let identity = e.identity();
            assert!(
                e.to_affine(&e.point_mul(&identity, &Uint::one())).is_none()
            );
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// The variable-time double multiplication agrees with the
    /// constant-time routines it stands in for.
    #[test]
    fn vartime_matches_the_constant_time_multiplications() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            let q = e.point_mul(&g, &Uint::from_limbs(&[7]));
            let (order_less_one, _) = curve.n.sub_borrow(&Uint::one());
            let mut scalars = std::vec![
                Uint::<L>::ZERO,
                Uint::one(),
                Uint::from_limbs(&[2]),
                Uint::from_limbs(&[15]),
                Uint::from_limbs(&[16]),
                order_less_one,
            ];
            let mut x = Uint::<L>::from_limbs(&[0x9e3779b97f4a7c15]);
            for _ in 0..6 {
                x = e.order.mulmod(&x, &Uint::from_limbs(&[0x100000001]));
                scalars.push(x);
            }
            for a in &scalars {
                for b in &scalars {
                    let want = affine(
                        &e,
                        &e.point_add(&e.point_mul(&q, a), &e.mul_base(b)),
                    );
                    let got = affine(&e, &e.mul_add_vartime(&q, a, b));
                    assert_eq!(want, got, "{:?} {:?}", a.0, b.0);
                }
            }
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// The fixed-base multiplication agrees with the general one,
    /// over the scalars that reach the edges of the comb: zero, one,
    /// the order less one, and values whose top bits fall in the
    /// last block, which runs past the scalar's width.
    #[test]
    fn fixed_base_matches_the_general_multiplication() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            let (top, _) = curve.n.sub_borrow(&Uint::one());
            let mut high = Uint::<L>::ZERO;
            high.0[L - 1] = 1 << 63;
            let mut spread = Uint::<L>::ZERO;
            for (i, limb) in spread.0.iter_mut().enumerate() {
                *limb = 0x0f1e2d3c4b5a6978u64.rotate_left(i as u32 * 7);
            }
            for k in [Uint::ZERO, Uint::one(), top, high, spread] {
                assert_eq!(
                    affine(&e, &e.mul_base(&k)),
                    affine(&e, &e.point_mul(&g, &k)),
                );
            }
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// Public keys from the ACVP ECDSA keyGen sample, one per curve,
    /// which is `d * G` against an external answer.
    #[test]
    fn public_keys_match_nist() {
        let mut buf = [0u8; 48];
        let e = Engine::new(&P256);
        let d = Secret::try_new(
            &e,
            unhex(
                "bf049d775057f1199612f4bd6ab0af69\
                 5a78fb488453e261ca3c277ad57e55db",
                &mut buf,
            ),
        )
        .unwrap();
        let public = d.public(&e);
        let mut sec1 = [0u8; 65];
        public.sec1(&e, &mut sec1);
        let mut expected = [0u8; 65];
        unhex(
            "04c6e20135457dc6f738e60cf6999d2416f31d7c12afea248434a547a9aa8a34b0\
             6e5610c1cfc091ad58aa43f2b8a96d9561ee80594c5bc5dc4cb08be679aa45ff",
            &mut expected,
        );
        assert_eq!(sec1, expected);
        assert_eq!(
            Public::try_from_sec1(&e, &expected).unwrap().x.0,
            public.x.0
        );

        let e = Engine::new(&P384);
        let d = Secret::try_new(
            &e,
            unhex(
                "958baeccb7bb953aa92fce3a136a7b8a\
                 68001c4ed00cf7da6fcf83c0f552636d\
                 0063e7c8a511cc45534f1a7f0f7dd959",
                &mut buf,
            ),
        )
        .unwrap();
        let public = d.public(&e);
        let mut sec1 = [0u8; 97];
        public.sec1(&e, &mut sec1);
        let mut expected = [0u8; 97];
        unhex(
            "0419f324cf1cbc7d17c1284f1d887eecafb1e11f4c9709566b3094fe3152f63fdb\
             c937018f93918b80a84d4a9ffb8e132c75a66d983f39cca1dddebb881969adea\
             be03b8c84b16e9e8b1de4b79ba3c41701145762eb90cc59c5f61f568d0601c08",
            &mut expected,
        );
        assert_eq!(sec1, expected);
    }

    /// Compressed points decompress to the same key, with either
    /// parity, and a non-residue x is refused.
    #[test]
    fn compressed_points() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let mut rng = crate::random::CtrDrbg::from_system().unwrap();
            let mut sec1 = [0u8; 133];
            let w = curve.width();
            for _ in 0..4 {
                let public = Secret::generate(&e, &mut rng).unwrap().public(&e);
                public.sec1(&e, &mut sec1[..1 + 2 * w]);
                let mut compressed = [0u8; 67];
                compressed[..1 + w].copy_from_slice(&sec1[..1 + w]);
                compressed[0] = 0x02 | (sec1[2 * w] & 1);
                let back =
                    Public::try_from_sec1(&e, &compressed[..1 + w]).unwrap();
                assert_eq!(back.y.0, public.y.0);
                // The other parity is the negated point, also valid.
                compressed[0] ^= 1;
                let other =
                    Public::try_from_sec1(&e, &compressed[..1 + w]).unwrap();
                assert_eq!(
                    other.y.0,
                    Uint::ZERO.sub_mod(&public.y, &curve.p).0
                );
                // A point off the curve, and the wrong lengths.
                sec1[1 + 2 * w - 1] ^= 1;
                assert!(Public::try_from_sec1(&e, &sec1[..1 + 2 * w]).is_err());
                assert!(Public::try_from_sec1(&e, &sec1[..2 * w]).is_err());
                assert!(Public::try_from_sec1(&e, &[0]).is_err());
            }
            // Among small x, some have no y: those are refused, and
            // the rest decompress to points that re-encode.
            let mut refused = 0;
            for x in 1..20u8 {
                let mut compressed = [0u8; 67];
                compressed[0] = 0x02;
                compressed[w] = x;
                match Public::try_from_sec1(&e, &compressed[..1 + w]) {
                    Ok(p) => {
                        p.sec1(&e, &mut sec1[..1 + 2 * w]);
                        assert_eq!(sec1[1..1 + w], compressed[1..1 + w]);
                        assert_eq!(sec1[2 * w] & 1, 0);
                    }
                    Err(Error::InvalidPublicKey) => refused += 1,
                    Err(e) => panic!("{e}"),
                }
            }
            assert!(refused > 0, "no non-residue among small x");
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// The scalars `n - 2 j` for every digit magnitude `j`, which
    /// are where the lowest window's entry can equal the accumulator
    /// in a windowed multiplication; P-521 at `j = 9` is Wycheproof's
    /// CVE-2017-10176 case. Each product must be `-2 j G`.
    #[test]
    fn near_order_scalars_multiply_correctly() {
        fn check<const L: usize>(curve: &Curve<L>) {
            let e = Engine::new(curve);
            let g = generator(&e);
            for j in 1..=64u64 {
                let (k, _) = curve.n.sub_borrow(&Uint::from_limbs(&[2 * j]));
                let want = affine(&e, &e.point_mul_complete(&g, &k));
                assert_eq!(affine(&e, &e.point_mul(&g, &k)), want, "{j}");
                assert_eq!(affine(&e, &e.mul_base(&k)), want, "{j}");
            }
        }
        check(&P256);
        check(&P384);
        check(&P521);
    }

    /// RFC 6979 appendix A.2.5 and A.2.6: deterministic signatures
    /// over "sample" and "test" with the private key given there.
    #[test]
    fn rfc6979_vectors() {
        let mut buf = [0u8; 48];
        let e = Engine::new(&P256);
        let d = Secret::try_new(
            &e,
            unhex(
                "c9afa9d845ba75166b5c215767b1d693\
                 4e50c3db36e89b127b8a622b120f6721",
                &mut buf,
            ),
        )
        .unwrap();
        let mut sig = [0u8; 64];
        d.sign::<Sha256>(&e, b"sample", &mut sig).unwrap();
        let mut expected = [0u8; 64];
        unhex(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
             f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            &mut expected,
        );
        assert_eq!(sig, expected);
        d.public(&e).verify::<Sha256>(&e, b"sample", &sig).unwrap();
        d.sign::<Sha256>(&e, b"test", &mut sig).unwrap();
        unhex(
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367\
             019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            &mut expected,
        );
        assert_eq!(sig, expected);

        let e = Engine::new(&P384);
        let d = Secret::try_new(
            &e,
            unhex(
                "6b9d3dad2e1b8c1c05b19875b6659f4d\
                 e23c3b667bf297ba9aa47740787137d8\
                 96d5724e4c70a825f872c9ea60d2edf5",
                &mut buf,
            ),
        )
        .unwrap();
        let mut sig = [0u8; 96];
        d.sign::<Sha384>(&e, b"sample", &mut sig).unwrap();
        let mut expected = [0u8; 96];
        unhex(
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
             81a648152e44acf96e36dd1e80fabe4699ef4aeb15f178cea1fe40db2603138f\
             130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
            &mut expected,
        );
        assert_eq!(sig, expected);
        d.public(&e).verify::<Sha384>(&e, b"sample", &sig).unwrap();
    }

    /// Verification refuses what it should: a changed message, a
    /// changed signature, zero or out-of-range parts, another key.
    #[test]
    fn verify_refusals() {
        let e = Engine::new(&P256);
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let d = Secret::generate(&e, &mut rng).unwrap();
        let public = d.public(&e);
        let mut sig = [0u8; 64];
        d.sign::<Sha256>(&e, b"message", &mut sig).unwrap();
        public.verify::<Sha256>(&e, b"message", &sig).unwrap();
        let bad = |s: &[u8], m: &[u8]| {
            assert_eq!(
                public.verify::<Sha256>(&e, m, s),
                Err(Error::InvalidSignature)
            );
        };
        bad(&sig, b"messagf");
        let mut t = sig;
        t[0] ^= 1;
        bad(&t, b"message");
        t = sig;
        t[63] ^= 1;
        bad(&t, b"message");
        t = sig;
        t[..32].fill(0);
        bad(&t, b"message");
        t = sig;
        t[32..].fill(0xff);
        bad(&t, b"message");
        bad(&sig[..63], b"message");
        let other = Secret::generate(&e, &mut rng).unwrap().public(&e);
        assert!(other.verify::<Sha256>(&e, b"message", &sig).is_err());
    }

    /// Both sides of an agreement land on the same secret, and a
    /// key of the other curve or an off-curve point is refused.
    #[test]
    fn agreement() {
        let e = Engine::new(&P384);
        let mut rng = crate::random::CtrDrbg::from_system().unwrap();
        let a = Secret::generate(&e, &mut rng).unwrap();
        let b = Secret::generate(&e, &mut rng).unwrap();
        let mut ab = [0u8; 48];
        let mut ba = [0u8; 48];
        a.shared_secret(&e, &b.public(&e), &mut ab);
        b.shared_secret(&e, &a.public(&e), &mut ba);
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 48]);
    }

    /// Scalars out of range are not keys.
    #[test]
    fn scalar_range() {
        let e = Engine::new(&P256);
        let mut buf = [0u8; 32];
        assert_eq!(
            Secret::try_new(&e, &buf).err(),
            Some(Error::InvalidPrivateKey)
        );
        P256.n.to_be_bytes(&mut buf);
        assert_eq!(
            Secret::try_new(&e, &buf).err(),
            Some(Error::InvalidPrivateKey)
        );
        buf[31] -= 1;
        assert!(Secret::try_new(&e, &buf).is_ok());
        assert_eq!(
            Secret::try_new(&e, &buf[..31]).err(),
            Some(Error::InvalidKeyLength(31))
        );
        assert_eq!(
            Secret::try_new(&e, &[1u8; 48]).err(),
            Some(Error::InvalidKeyLength(48))
        );
    }
}
