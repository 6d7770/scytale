//! DER, as much of it as keys need: a reader for the importers, a
//! writer for the exporters, and the two containers every key here
//! travels in, `SubjectPublicKeyInfo` (RFC 5280) and PKCS#8
//! `PrivateKeyInfo` (RFC 5208, extended by RFC 5958). The RFC 8410
//! shapes for the two curves are here too, since Ed25519 and X25519
//! share them down to the byte.
//!
//! Private to the crate: the key types expose the formats, not the
//! encoding.
//!
//! The reader is strict, because DER is the encoding with one right
//! answer: definite lengths only and in their shortest form,
//! integers in theirs, and nothing left over. A structure that
//! bends any of those is refused as [`Error::InvalidEncoding`]
//! rather than read charitably, since a key that parses two ways is
//! a key that two parties disagree about.
//!
//! The writer has no allocator to hold a body in while its length
//! is worked out, and DER puts the length first, so every nested
//! structure is written twice: once into nothing to measure it and
//! once for real. Nesting is four deep at most, so the cost is
//! nothing.

use zeroize::Zeroize;

use crate::Error;
use crate::codec::pem;

// The universal tags in use.
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OBJECT_IDENTIFIER: u8 = 0x06;
const SEQUENCE: u8 = 0x30;

/// The tag of a constructed context-specific element, `[n]`.
pub(crate) const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// The tag of a primitive context-specific element, `[n] IMPLICIT`
/// over a primitive type.
pub(crate) const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// The contents of the OID `rsaEncryption`, 1.2.840.113549.1.1.1.
pub(crate) const RSA_ENCRYPTION: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// The contents of the OID `id-RSASSA-PSS`, 1.2.840.113549.1.1.10.
pub(crate) const RSASSA_PSS: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

/// The contents of the OID `id-X25519`, 1.3.101.110.
pub(crate) const X25519: [u8; 3] = [0x2b, 0x65, 0x6e];

/// The contents of the OID `id-Ed25519`, 1.3.101.112.
pub(crate) const ED25519: [u8; 3] = [0x2b, 0x65, 0x70];

/// The bytes a length of `n` takes: one below 128, otherwise one
/// for the count of bytes and then the bytes themselves.
const fn length_len(n: usize) -> usize {
    if n < 128 {
        1
    } else if n < 1 << 8 {
        2
    } else if n < 1 << 16 {
        3
    } else {
        4
    }
}

/// The length of an element whose contents are `contents` long:
/// tag, length and contents.
pub(crate) const fn tlv_len(contents: usize) -> usize {
    1 + length_len(contents) + contents
}

/// The length of a SubjectPublicKeyInfo whose algorithm is an OID
/// of `oid` bytes with no parameters, around a key of `key` bytes.
pub(crate) const fn spki_len(oid: usize, key: usize) -> usize {
    tlv_len(tlv_len(tlv_len(oid)) + tlv_len(1 + key))
}

/// The length of a version 0 PrivateKeyInfo whose algorithm is an
/// OID of `oid` bytes with no parameters, around a privateKey whose
/// contents are `key` bytes.
pub(crate) const fn pkcs8_len(oid: usize, key: usize) -> usize {
    tlv_len(tlv_len(1) + tlv_len(tlv_len(oid)) + tlv_len(key))
}

/// A cursor over encoded bytes. Each call consumes one element and
/// hands back its contents; a constructed element comes back as a
/// reader over those contents.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The contents of the next element, which must carry `tag`.
    pub(crate) fn element(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        if self.peek() != Some(tag) {
            return Err(Error::InvalidEncoding);
        }
        let (len, header) = length(&self.data[1..])?;
        let start = 1 + header;
        let end = start.checked_add(len).ok_or(Error::InvalidEncoding)?;
        let contents =
            self.data.get(start..end).ok_or(Error::InvalidEncoding)?;
        self.data = &self.data[end..];
        Ok(contents)
    }

    /// [`element`](Self::element) when the next tag is `tag`, and
    /// `None` when it is anything else, for OPTIONAL fields.
    pub(crate) fn optional(
        &mut self,
        tag: u8,
    ) -> Result<Option<&'a [u8]>, Error> {
        if self.peek() == Some(tag) {
            self.element(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn sequence(&mut self) -> Result<Reader<'a>, Error> {
        self.element(SEQUENCE).map(Reader::new)
    }

    /// A SEQUENCE when one is next, for a CHOICE that has one arm.
    pub(crate) fn optional_sequence(
        &mut self,
    ) -> Result<Option<Reader<'a>>, Error> {
        Ok(self.optional(SEQUENCE)?.map(Reader::new))
    }

    /// A non-negative INTEGER as its big-endian magnitude, with the
    /// sign byte gone: zero is the one byte `0`.
    ///
    /// Keys hold no negative numbers, so a negative one is refused
    /// rather than read. A leading zero byte that the sign does not
    /// require is refused too, as DER requires.
    pub(crate) fn integer(&mut self) -> Result<&'a [u8], Error> {
        match self.element(INTEGER)? {
            [] => Err(Error::InvalidEncoding),
            [first, ..] if first & 0x80 != 0 => Err(Error::InvalidEncoding),
            [0, next, ..] if next & 0x80 == 0 => Err(Error::InvalidEncoding),
            [0, rest @ ..] if !rest.is_empty() => Ok(rest),
            contents => Ok(contents),
        }
    }

    pub(crate) fn octet_string(&mut self) -> Result<&'a [u8], Error> {
        self.element(OCTET_STRING)
    }

    /// A BIT STRING that is a whole number of bytes, which every key
    /// is; the unused-bits count must say zero.
    pub(crate) fn bit_string(&mut self) -> Result<&'a [u8], Error> {
        bit_string_contents(self.element(BIT_STRING)?)
    }

    /// An OBJECT IDENTIFIER's contents, for comparing with a known
    /// one; nothing here needs to decode the arcs.
    pub(crate) fn oid(&mut self) -> Result<&'a [u8], Error> {
        match self.element(OBJECT_IDENTIFIER)? {
            [] => Err(Error::InvalidEncoding),
            contents => Ok(contents),
        }
    }

    /// Whatever has not been read, without reading it.
    pub(crate) fn rest(self) -> &'a [u8] {
        self.data
    }

    /// Nothing may follow the last field of a structure.
    pub(crate) fn end(&self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

/// The unused-bits byte checked and removed.
fn bit_string_contents(contents: &[u8]) -> Result<&[u8], Error> {
    match contents {
        [0, bits @ ..] => Ok(bits),
        _ => Err(Error::InvalidEncoding),
    }
}

/// A definite length and the number of bytes it took.
///
/// The indefinite form is BER, not DER. A long form is refused when
/// the short form would have done, or when a leading byte is zero,
/// both of which DER forbids; and one over four bytes names a
/// length no key reaches.
fn length(data: &[u8]) -> Result<(usize, usize), Error> {
    let first = *data.first().ok_or(Error::InvalidEncoding)?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return Err(Error::InvalidEncoding);
    }
    let bytes = data.get(1..1 + count).ok_or(Error::InvalidEncoding)?;
    if bytes[0] == 0 {
        return Err(Error::InvalidEncoding);
    }
    let mut len = 0usize;
    for &b in bytes {
        len = (len << 8) | usize::from(b);
    }
    if len < 0x80 {
        return Err(Error::InvalidEncoding);
    }
    Ok((len, 1 + count))
}

/// An encoder over a buffer, or over nothing when measuring.
pub(crate) struct Writer<'a> {
    out: Option<&'a mut [u8]>,
    len: usize,
}

/// Encodes what `body` writes into `out`, returning the length, or
/// [`Error::OutputTooSmall`] with the length it would need.
pub(crate) fn encode(
    out: &mut [u8],
    body: impl Fn(&mut Writer),
) -> Result<usize, Error> {
    let needed = measure(&body);
    if out.len() < needed {
        return Err(Error::OutputTooSmall(needed));
    }
    let mut writer = Writer {
        out: Some(out),
        len: 0,
    };
    body(&mut writer);
    debug_assert_eq!(writer.len, needed);
    Ok(needed)
}

/// The length `body` writes, found by writing it into nothing.
fn measure(body: &impl Fn(&mut Writer)) -> usize {
    let mut writer = Writer { out: None, len: 0 };
    body(&mut writer);
    writer.len
}

impl Writer<'_> {
    /// Bytes as they are, with no tag or length. The buffer is known
    /// to hold them: [`encode`] measured the whole before writing.
    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        if let Some(out) = self.out.as_deref_mut() {
            out[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        }
        self.len += bytes.len();
    }

    fn header(&mut self, tag: u8, len: usize) {
        self.raw(&[tag]);
        if len < 0x80 {
            self.raw(&[len as u8]);
            return;
        }
        let bytes = len.to_be_bytes();
        // Nonzero, since the short form was ruled out.
        let skip = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        self.raw(&[0x80 | (bytes.len() - skip) as u8]);
        self.raw(&bytes[skip..]);
    }

    /// A primitive element of any tag.
    pub(crate) fn primitive(&mut self, tag: u8, contents: &[u8]) {
        self.header(tag, contents.len());
        self.raw(contents);
    }

    /// An element whose contents are `prefix` and then whatever
    /// `body` writes, measured first so the length can lead.
    fn wrapped(&mut self, tag: u8, prefix: &[u8], body: impl Fn(&mut Writer)) {
        self.header(tag, prefix.len() + measure(&body));
        self.raw(prefix);
        body(self);
    }

    pub(crate) fn sequence(&mut self, body: impl Fn(&mut Writer)) {
        self.wrapped(SEQUENCE, &[], body);
    }

    /// An OCTET STRING holding an encoding of its own, as PKCS#8
    /// wraps the algorithm's private key.
    pub(crate) fn octet_string_of(&mut self, body: impl Fn(&mut Writer)) {
        self.wrapped(OCTET_STRING, &[], body);
    }

    /// A BIT STRING holding an encoding of its own, as
    /// SubjectPublicKeyInfo wraps the algorithm's public key.
    pub(crate) fn bit_string_of(&mut self, body: impl Fn(&mut Writer)) {
        self.wrapped(BIT_STRING, &[0], body);
    }

    /// A non-negative INTEGER from its big-endian magnitude, however
    /// many leading zeros it comes with: the encoding drops them
    /// and adds the one sign byte a set top bit needs.
    pub(crate) fn integer(&mut self, magnitude: &[u8]) {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let magnitude = &magnitude[start..];
        match magnitude {
            [] => self.primitive(INTEGER, &[0]),
            [first, ..] if first & 0x80 != 0 => {
                self.header(INTEGER, magnitude.len() + 1);
                self.raw(&[0]);
                self.raw(magnitude);
            }
            _ => self.primitive(INTEGER, magnitude),
        }
    }

    pub(crate) fn oid(&mut self, contents: &[u8]) {
        self.primitive(OBJECT_IDENTIFIER, contents);
    }

    pub(crate) fn octet_string(&mut self, contents: &[u8]) {
        self.primitive(OCTET_STRING, contents);
    }

    /// A BIT STRING of whole bytes.
    pub(crate) fn bit_string(&mut self, contents: &[u8]) {
        self.header(BIT_STRING, contents.len() + 1);
        self.raw(&[0]);
        self.raw(contents);
    }

    /// A constructed `[n]` element around what `body` writes.
    pub(crate) fn context(&mut self, n: u8, body: impl Fn(&mut Writer)) {
        self.wrapped(context(n), &[], body);
    }

    pub(crate) fn null(&mut self) {
        self.primitive(NULL, &[]);
    }
}

/// An AlgorithmIdentifier's parts: the OID's contents, and whatever
/// parameters follow it, unread and empty when there are none.
pub(crate) struct Algorithm<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) params: &'a [u8],
}

impl Algorithm<'_> {
    /// Whether the parameters are absent or a NULL. RFC 8017 says
    /// `rsaEncryption` takes a NULL, and enough writers leave it out
    /// that an RSA reader accepts either; this is for that reader.
    pub(crate) fn absent_or_null_params(&self) -> bool {
        self.params.is_empty() || self.params == [NULL, 0]
    }

    /// Whether the parameters are absent, which RFC 8410 requires of
    /// the curve algorithms: a NULL there is a defect the RFC names
    /// and says not to propagate, so it is not read either.
    pub(crate) fn absent_params(&self) -> bool {
        self.params.is_empty()
    }
}

fn algorithm<'a>(reader: &mut Reader<'a>) -> Result<Algorithm<'a>, Error> {
    let mut alg = reader.sequence()?;
    let oid = alg.oid()?;
    Ok(Algorithm {
        oid,
        params: alg.rest(),
    })
}

/// The body of an AlgorithmIdentifier that is an OID and, when
/// `null`, a NULL.
fn algorithm_identifier(w: &mut Writer, oid: &[u8], null: bool) {
    w.oid(oid);
    if null {
        w.null();
    }
}

/// A whole SubjectPublicKeyInfo: its algorithm and the bytes of its
/// subjectPublicKey.
pub(crate) fn read_spki(der: &[u8]) -> Result<(Algorithm<'_>, &[u8]), Error> {
    let mut outer = Reader::new(der);
    let mut info = outer.sequence()?;
    outer.end()?;
    let algorithm = algorithm(&mut info)?;
    let key = info.bit_string()?;
    info.end()?;
    Ok((algorithm, key))
}

/// Writes a SubjectPublicKeyInfo whose subjectPublicKey `key`
/// writes; `null` says whether the algorithm takes a NULL parameter.
pub(crate) fn write_spki(
    out: &mut [u8],
    oid: &[u8],
    null: bool,
    key: impl Fn(&mut Writer),
) -> Result<usize, Error> {
    write_spki_with(out, |w| algorithm_identifier(w, oid, null), key)
}

/// [`write_spki`] with the AlgorithmIdentifier's body written by
/// `algorithm`, for the algorithms whose parameters are more than
/// a NULL.
pub(crate) fn write_spki_with(
    out: &mut [u8],
    algorithm: impl Fn(&mut Writer),
    key: impl Fn(&mut Writer),
) -> Result<usize, Error> {
    encode(out, |w| {
        w.sequence(|w| {
            w.sequence(&algorithm);
            w.bit_string_of(&key);
        })
    })
}

/// Which form a PKCS#8 `PrivateKeyInfo` took, for a caller whose own
/// rules are stricter than the standard's: one that requires the
/// version 1 form, or the public key, may ask. Every reader here
/// takes either version and checks a public key when one is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pkcs8Form {
    /// Whether it was version 1, RFC 5958's OneAsymmetricKey.
    pub v1: bool,
    /// Whether it carried the public key, which was then checked
    /// against the private one.
    pub public_key: bool,
}

/// A whole PKCS#8 PrivateKeyInfo.
pub(crate) struct Pkcs8<'a> {
    pub(crate) algorithm: Algorithm<'a>,
    /// The privateKey OCTET STRING's contents, an encoding of the
    /// algorithm's own.
    pub(crate) private_key: &'a [u8],
    /// Whether the structure is version 1, RFC 5958's
    /// OneAsymmetricKey, which is the form that may carry a public
    /// key.
    pub(crate) v1: bool,
    /// The public key a version 1 structure may carry.
    pub(crate) public_key: Option<&'a [u8]>,
}

pub(crate) fn read_pkcs8(der: &[u8]) -> Result<Pkcs8<'_>, Error> {
    let mut outer = Reader::new(der);
    let mut info = outer.sequence()?;
    outer.end()?;
    // Version 1 is RFC 5958's OneAsymmetricKey, which adds the
    // public key; the two read alike up to that field.
    let v1 = match info.integer()? {
        [0] => false,
        [1] => true,
        _ => return Err(Error::UnsupportedVersion),
    };
    let algorithm = algorithm(&mut info)?;
    let private_key = info.octet_string()?;
    // Attributes say nothing about the key and are skipped.
    info.optional(context(0))?;
    let public_key = if v1 {
        info.optional(context_primitive(1))?
            .map(bit_string_contents)
            .transpose()?
    } else {
        None
    };
    info.end()?;
    Ok(Pkcs8 {
        algorithm,
        private_key,
        v1,
        public_key,
    })
}

/// Writes a version 0 PrivateKeyInfo whose privateKey `key` writes;
/// `null` says whether the algorithm takes a NULL parameter.
pub(crate) fn write_pkcs8(
    out: &mut [u8],
    oid: &[u8],
    null: bool,
    key: impl Fn(&mut Writer),
) -> Result<usize, Error> {
    write_pkcs8_with(out, |w| algorithm_identifier(w, oid, null), key)
}

/// [`write_pkcs8`] with the AlgorithmIdentifier's body written by
/// `algorithm`.
pub(crate) fn write_pkcs8_with(
    out: &mut [u8],
    algorithm: impl Fn(&mut Writer),
    key: impl Fn(&mut Writer),
) -> Result<usize, Error> {
    encode(out, |w| {
        w.sequence(|w| {
            w.integer(&[0]);
            w.sequence(&algorithm);
            w.octet_string_of(&key);
        })
    })
}

/// Which forms of a private key a PKCS#8 carried, for the
/// post-quantum schemes whose keys RFC 9881 (ML-DSA) and RFC 9935
/// (ML-KEM) write as a CHOICE: `[0]` the seed alone, an OCTET STRING
/// the expanded key alone, or a SEQUENCE of both, in which the seed
/// is a plain OCTET STRING. Drafts before the RFCs tagged that seed
/// `[0]` too; that form is refused.
pub(crate) struct SeedOrExpanded<'a> {
    pub(crate) seed: Option<&'a [u8]>,
    pub(crate) expanded: Option<&'a [u8]>,
}

pub(crate) fn read_seed_or_expanded(
    der: &[u8],
) -> Result<SeedOrExpanded<'_>, Error> {
    let mut outer = Reader::new(der);
    let forms = if let Some(seed) = outer.optional(context_primitive(0))? {
        SeedOrExpanded {
            seed: Some(seed),
            expanded: None,
        }
    } else if let Some(mut both) = outer.optional_sequence()? {
        let seed = both.octet_string()?;
        let expanded = both.octet_string()?;
        both.end()?;
        SeedOrExpanded {
            seed: Some(seed),
            expanded: Some(expanded),
        }
    } else {
        SeedOrExpanded {
            seed: None,
            expanded: Some(outer.octet_string()?),
        }
    };
    outer.end()?;
    Ok(forms)
}

/// The width of an RFC 8410 curve key, secret or public.
const CURVE_KEY: usize = 32;

/// The length of a curve key's PrivateKeyInfo.
pub(crate) const CURVE_SECRET_DER: usize = 48;

/// The length of a curve key's SubjectPublicKeyInfo.
pub(crate) const CURVE_PUBLIC_DER: usize = 44;

/// A curve secret from its PrivateKeyInfo, with the public key the
/// structure carried if it was version 1, for the caller to check
/// against the secret.
///
/// RFC 8410 wraps the seed in an OCTET STRING of its own,
/// `CurvePrivateKey`, inside the one PKCS#8 provides, and that is
/// required here: a bare seed is a different, wrong, encoding.
pub(crate) fn curve_secret_from_der(
    oid: &[u8; 3],
    der: &[u8],
) -> Result<CurveSecret, Error> {
    let info = read_pkcs8(der)?;
    if info.algorithm.oid != oid || !info.algorithm.absent_params() {
        return Err(Error::WrongAlgorithm);
    }
    let mut inner = Reader::new(info.private_key);
    let seed = inner.octet_string()?;
    inner.end()?;
    let secret = seed.try_into().map_err(|_| Error::InvalidEncoding)?;
    let public = info
        .public_key
        .map(|p| p.try_into().map_err(|_| Error::InvalidEncoding))
        .transpose()?;
    Ok(CurveSecret {
        secret,
        public,
        v1: info.v1,
    })
}

/// What a curve PrivateKeyInfo held.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) struct CurveSecret {
    pub(crate) secret: [u8; CURVE_KEY],
    /// The public key it carried, which only a version 1 structure
    /// can.
    pub(crate) public: Option<[u8; CURVE_KEY]>,
    /// Whether it was version 1.
    pub(crate) v1: bool,
}

/// A curve secret's version 0 PrivateKeyInfo, which is fixed down
/// to the byte: the framing, then the seed.
pub(crate) fn curve_secret_der(
    oid: &[u8; 3],
    secret: &[u8; CURVE_KEY],
) -> [u8; CURVE_SECRET_DER] {
    let mut out = [0u8; CURVE_SECRET_DER];
    out[..16].copy_from_slice(&[
        0x30, 46, 0x02, 1, 0, 0x30, 5, 0x06, 3, oid[0], oid[1], oid[2], 0x04,
        34, 0x04, 32,
    ]);
    out[16..].copy_from_slice(secret);
    out
}

/// The length of a curve secret's version 1 PrivateKeyInfo, which
/// carries the public key beside the seed.
pub(crate) const CURVE_PAIR_DER: usize = 83;

/// A curve secret and its public key as a version 1 PrivateKeyInfo,
/// RFC 5958's `OneAsymmetricKey`, fixed down to the byte.
///
/// The version 0 form above is what OpenSSL writes and is enough on
/// its own. This one carries the public key as well, which some
/// readers require and which lets a reader check the pair agrees.
pub(crate) fn curve_pair_der(
    oid: &[u8; 3],
    secret: &[u8; CURVE_KEY],
    public: &[u8; CURVE_KEY],
) -> [u8; CURVE_PAIR_DER] {
    let mut out = [0u8; CURVE_PAIR_DER];
    out[..16].copy_from_slice(&[
        0x30, 81, 0x02, 1, 1, 0x30, 5, 0x06, 3, oid[0], oid[1], oid[2], 0x04,
        34, 0x04, 32,
    ]);
    out[16..48].copy_from_slice(secret);
    // [1] IMPLICIT BIT STRING, with no unused bits.
    out[48..51].copy_from_slice(&[0x81, 33, 0]);
    out[51..].copy_from_slice(public);
    out
}

/// A curve public key from its SubjectPublicKeyInfo.
pub(crate) fn curve_public_from_der(
    oid: &[u8; 3],
    der: &[u8],
) -> Result<[u8; CURVE_KEY], Error> {
    let (algorithm, key) = read_spki(der)?;
    if algorithm.oid != oid || !algorithm.absent_params() {
        return Err(Error::WrongAlgorithm);
    }
    key.try_into().map_err(|_| Error::InvalidEncoding)
}

/// A curve public key's SubjectPublicKeyInfo, fixed down to the
/// byte.
pub(crate) fn curve_public_der(
    oid: &[u8; 3],
    public: &[u8; CURVE_KEY],
) -> [u8; CURVE_PUBLIC_DER] {
    let mut out = [0u8; CURVE_PUBLIC_DER];
    out[..12].copy_from_slice(&[
        0x30, 42, 0x30, 5, 0x06, 3, oid[0], oid[1], oid[2], 0x03, 33, 0,
    ]);
    out[12..].copy_from_slice(public);
    out
}

/// The length of a curve secret's PEM block.
pub(crate) const CURVE_SECRET_PEM: usize = 119;

/// The length of a curve public key's PEM block.
pub(crate) const CURVE_PUBLIC_PEM: usize = 113;

const PRIVATE_KEY: &str = "PRIVATE KEY";
const PUBLIC_KEY: &str = "PUBLIC KEY";

/// Room to decode a curve PrivateKeyInfo into: the version 0 form
/// is 48 bytes and the version 1 form 83, but the attributes a
/// version 1 structure may carry have no bound, so this allows a
/// generous one. A block past it is refused as malformed.
const CURVE_SECRET_SCRATCH: usize = 512;

/// [`curve_secret_from_der`] through a `PRIVATE KEY` PEM block.
pub(crate) fn curve_secret_from_pem(
    oid: &[u8; 3],
    pem: &[u8],
) -> Result<CurveSecret, Error> {
    let mut der = [0u8; CURVE_SECRET_SCRATCH];
    let result = pem::decode_one_of(&[PRIVATE_KEY], pem, &mut der)
        .and_then(|(_, n)| curve_secret_from_der(oid, &der[..n]));
    der.zeroize();
    result
}

/// [`curve_secret_der`] as a `PRIVATE KEY` PEM block.
pub(crate) fn curve_secret_pem(
    oid: &[u8; 3],
    secret: &[u8; CURVE_KEY],
) -> [u8; CURVE_SECRET_PEM] {
    let mut der = curve_secret_der(oid, secret);
    let mut out = [0u8; CURVE_SECRET_PEM];
    let n = pem::encode_exact(PRIVATE_KEY, &der, &mut out);
    debug_assert_eq!(n, CURVE_SECRET_PEM);
    der.zeroize();
    out
}

/// The length of a curve key pair's PEM block.
pub(crate) const CURVE_PAIR_PEM: usize = 168;

/// [`curve_pair_der`] in a `PRIVATE KEY` PEM block.
pub(crate) fn curve_pair_pem(
    oid: &[u8; 3],
    secret: &[u8; CURVE_KEY],
    public: &[u8; CURVE_KEY],
) -> [u8; CURVE_PAIR_PEM] {
    let mut der = curve_pair_der(oid, secret, public);
    let mut out = [0u8; CURVE_PAIR_PEM];
    let n = pem::encode_exact(PRIVATE_KEY, &der, &mut out);
    debug_assert_eq!(n, CURVE_PAIR_PEM);
    der.zeroize();
    out
}

/// [`curve_public_from_der`] through a `PUBLIC KEY` PEM block.
pub(crate) fn curve_public_from_pem(
    oid: &[u8; 3],
    pem: &[u8],
) -> Result<[u8; CURVE_KEY], Error> {
    let mut der = [0u8; CURVE_PUBLIC_DER];
    let (_, n) = pem::decode_one_of(&[PUBLIC_KEY], pem, &mut der)?;
    curve_public_from_der(oid, &der[..n])
}

/// [`curve_public_der`] as a `PUBLIC KEY` PEM block.
pub(crate) fn curve_public_pem(
    oid: &[u8; 3],
    public: &[u8; CURVE_KEY],
) -> [u8; CURVE_PUBLIC_PEM] {
    let der = curve_public_der(oid, public);
    let mut out = [0u8; CURVE_PUBLIC_PEM];
    let n = pem::encode_exact(PUBLIC_KEY, &der, &mut out);
    debug_assert_eq!(n, CURVE_PUBLIC_PEM);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read<'a>(
        bytes: &'a [u8],
        f: impl Fn(&mut Reader<'a>) -> Result<&'a [u8], Error>,
    ) -> Result<&'a [u8], Error> {
        let mut r = Reader::new(bytes);
        let out = f(&mut r)?;
        r.end()?;
        Ok(out)
    }

    #[test]
    fn integers_read_minimally() {
        let int = |b: &'static [u8]| read(b, |r| r.integer());
        assert_eq!(int(&[0x02, 0x01, 0x00]), Ok(&[0u8][..]));
        assert_eq!(int(&[0x02, 0x01, 0x7f]), Ok(&[0x7fu8][..]));
        assert_eq!(int(&[0x02, 0x02, 0x00, 0x80]), Ok(&[0x80u8][..]));
        assert_eq!(int(&[0x02, 0x02, 0x01, 0x00]), Ok(&[0x01u8, 0x00][..]));
        // Empty, negative, and a leading zero the sign does not need.
        assert_eq!(int(&[0x02, 0x00]), Err(Error::InvalidEncoding));
        assert_eq!(int(&[0x02, 0x01, 0x80]), Err(Error::InvalidEncoding));
        assert_eq!(int(&[0x02, 0x02, 0x00, 0x01]), Err(Error::InvalidEncoding));
        assert_eq!(int(&[0x02, 0x02, 0x00, 0x00]), Err(Error::InvalidEncoding));
    }

    #[test]
    fn lengths_are_definite_and_shortest() {
        let octets = |b: &[u8]| read(b, |r| r.octet_string()).map(|c| c.len());
        assert_eq!(octets(&[0x04, 0x00]), Ok(0));
        let mut long = [0xabu8; 131];
        long[..3].copy_from_slice(&[0x04, 0x81, 0x80]);
        assert_eq!(octets(&long), Ok(128));
        // Indefinite; long form for a short length; a leading zero in
        // the length; five length bytes; a length past the end; and
        // trailing bytes after the element.
        for bad in [
            &[0x04, 0x80, 0x00, 0x00][..],
            &[0x04, 0x81, 0x01, 0xab],
            &[0x04, 0x82, 0x00, 0x01, 0xab],
            &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x04, 0x02, 0xab],
            &[0x04, 0x01, 0xab, 0x00],
            &[0x04],
            &[],
        ] {
            assert_eq!(octets(bad), Err(Error::InvalidEncoding), "{bad:02x?}");
        }
    }

    #[test]
    fn wrong_tag_is_refused() {
        assert_eq!(
            read(&[0x04, 0x01, 0x00], |r| r.integer()),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            read(&[0x03, 0x02, 0x01, 0x00], |r| r.bit_string()),
            Err(Error::InvalidEncoding),
            "unused bits"
        );
        assert_eq!(
            read(&[0x03, 0x00], |r| r.bit_string()),
            Err(Error::InvalidEncoding),
            "no unused-bits byte"
        );
        let mut r = Reader::new(&[0x06, 0x00]);
        assert_eq!(r.oid(), Err(Error::InvalidEncoding), "empty OID");
    }

    #[test]
    fn writer_matches_reader() {
        let mut out = [0u8; 300];
        let big = [0xffu8; 200];
        let n = encode(&mut out, |w| {
            w.sequence(|w| {
                w.integer(&[0, 0, 0]);
                w.integer(&[0, 0x80]);
                w.integer(&[0x01, 0x00]);
                w.oid(RSA_ENCRYPTION);
                w.bit_string_of(|w| w.raw(&big));
            })
        })
        .unwrap();
        assert_eq!(n, 2 + 3 + 4 + 4 + 11 + (4 + 1 + 200));
        assert_eq!(&out[..4], &[0x30, 0x81, 0xe2, 0x02]);

        let mut outer = Reader::new(&out[..n]);
        let mut seq = outer.sequence().unwrap();
        outer.end().unwrap();
        assert_eq!(seq.integer().unwrap(), &[0]);
        assert_eq!(seq.integer().unwrap(), &[0x80]);
        assert_eq!(seq.integer().unwrap(), &[0x01, 0x00]);
        assert_eq!(seq.oid().unwrap(), RSA_ENCRYPTION);
        assert_eq!(seq.bit_string().unwrap(), &big);
        seq.end().unwrap();
    }

    #[test]
    fn writer_reports_the_length_it_needs() {
        let body = |w: &mut Writer| w.sequence(|w| w.integer(&[5]));
        assert_eq!(encode(&mut [], body), Err(Error::OutputTooSmall(5)));
        assert_eq!(encode(&mut [0u8; 4], body), Err(Error::OutputTooSmall(5)));
        let mut out = [0u8; 5];
        assert_eq!(encode(&mut out, body), Ok(5));
        assert_eq!(out, [0x30, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn long_lengths_round_trip() {
        // Two- and three-byte lengths: 256 and 65536 bytes of content.
        let mut out = [0u8; 65600];
        for len in [128usize, 255, 256, 65535, 65536] {
            let n = encode(&mut out, |w| {
                w.octet_string_of(|w| w.raw(out2(len)));
            })
            .unwrap();
            let mut r = Reader::new(&out[..n]);
            assert_eq!(r.octet_string().unwrap().len(), len, "{len}");
            r.end().unwrap();
        }
    }

    fn out2(len: usize) -> &'static [u8] {
        static ZEROS: [u8; 65536] = [0; 65536];
        &ZEROS[..len]
    }

    /// The fixed curve encodings are what the general writer makes.
    #[test]
    fn curve_shapes_match_the_writer() {
        let secret = [0x11u8; 32];
        let public = [0x22u8; 32];
        for oid in [ED25519, X25519] {
            let mut out = [0u8; 64];
            let n = write_pkcs8(&mut out, &oid, false, |w| {
                w.octet_string_of(|w| w.raw(&secret))
            })
            .unwrap();
            assert_eq!(out[..n], curve_secret_der(&oid, &secret));
            let n =
                write_spki(&mut out, &oid, false, |w| w.raw(&public)).unwrap();
            assert_eq!(out[..n], curve_public_der(&oid, &public));

            let back =
                curve_secret_from_der(&oid, &curve_secret_der(&oid, &secret))
                    .unwrap();
            assert_eq!(back.secret, secret);
            assert_eq!(back.public, None);
            assert!(!back.v1);
            assert_eq!(
                curve_public_from_der(&oid, &curve_public_der(&oid, &public)),
                Ok(public)
            );
        }
    }

    #[test]
    fn curve_refusals() {
        let secret = [0x11u8; 32];
        let good = curve_secret_der(&ED25519, &secret);
        // The other curve's OID; a bare seed without CurvePrivateKey;
        // a 31-byte seed; and NULL parameters, which RFC 8410 forbids.
        assert_eq!(
            curve_secret_from_der(&X25519, &good),
            Err(Error::WrongAlgorithm)
        );
        let mut bare = [0u8; 46];
        bare[..14].copy_from_slice(&[
            0x30, 44, 0x02, 1, 0, 0x30, 5, 0x06, 3, 0x2b, 0x65, 0x70, 0x04, 32,
        ]);
        bare[14..].copy_from_slice(&secret);
        assert_eq!(
            curve_secret_from_der(&ED25519, &bare),
            Err(Error::InvalidEncoding)
        );
        let mut short = [0u8; 47];
        short.copy_from_slice(&good[..47]);
        short[1] = 45;
        short[13] = 33;
        short[15] = 31;
        assert_eq!(
            curve_secret_from_der(&ED25519, &short),
            Err(Error::InvalidEncoding)
        );
        let mut with_null = [0u8; 50];
        with_null[..18].copy_from_slice(&[
            0x30, 48, 0x02, 1, 0, 0x30, 7, 0x06, 3, 0x2b, 0x65, 0x70, 0x05, 0,
            0x04, 34, 0x04, 32,
        ]);
        with_null[18..].copy_from_slice(&secret);
        assert_eq!(
            curve_secret_from_der(&ED25519, &with_null),
            Err(Error::WrongAlgorithm)
        );
    }

    /// A version 1 structure with attributes and a public key reads,
    /// and hands the public key back; version 0 may not carry one.
    #[test]
    fn pkcs8_version_one() {
        let secret = [0x11u8; 32];
        let public = [0x22u8; 32];
        let mut out = [0u8; 128];
        let n = encode(&mut out, |w| {
            w.sequence(|w| {
                w.integer(&[1]);
                w.sequence(|w| algorithm_identifier(w, &ED25519, false));
                w.octet_string_of(|w| {
                    w.wrapped(OCTET_STRING, &[], |w| w.raw(&secret))
                });
                w.wrapped(context(0), &[], |w| w.sequence(|_| {}));
                w.wrapped(context_primitive(1), &[0], |w| w.raw(&public));
            })
        })
        .unwrap();
        assert_eq!(
            curve_secret_from_der(&ED25519, &out[..n]),
            Ok(CurveSecret {
                secret,
                public: Some(public),
                v1: true
            })
        );
        // The same with version 0 has a field it may not have.
        out[4] = 0;
        assert_eq!(
            curve_secret_from_der(&ED25519, &out[..n]),
            Err(Error::InvalidEncoding)
        );
        // Version 2 does not exist.
        out[4] = 2;
        assert_eq!(
            curve_secret_from_der(&ED25519, &out[..n]),
            Err(Error::UnsupportedVersion)
        );
    }

    #[test]
    fn curve_pem_sizes_and_round_trips() {
        assert_eq!(
            pem::encoded_len(PRIVATE_KEY, CURVE_SECRET_DER),
            CURVE_SECRET_PEM
        );
        assert_eq!(
            pem::encoded_len(PUBLIC_KEY, CURVE_PUBLIC_DER),
            CURVE_PUBLIC_PEM
        );
        let secret = [0x33u8; 32];
        let public = [0x44u8; 32];
        for oid in [ED25519, X25519] {
            let pem = curve_secret_pem(&oid, &secret);
            assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
            assert_eq!(
                curve_secret_from_pem(&oid, &pem),
                Ok(CurveSecret {
                    secret,
                    public: None,
                    v1: false
                })
            );
            let pem = curve_public_pem(&oid, &public);
            assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"));
            assert_eq!(curve_public_from_pem(&oid, &pem), Ok(public));
            // The labels are not interchangeable.
            assert_eq!(
                curve_public_from_pem(&oid, &curve_secret_pem(&oid, &secret)),
                Err(Error::InvalidEncoding)
            );
        }
    }
}
