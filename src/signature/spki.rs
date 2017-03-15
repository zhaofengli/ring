// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use {der, Error};
use ring::signature;
use untrusted;

/// X.509 certificates and related items that are signed are almost always
/// encoded in the format "tbs||signatureAlgorithm||signature". This structure
/// captures this pattern.
pub struct SignedData<'a> {
    /// The signed data. This would be `tbsCertificate` in the case of an X.509
    /// certificate, `tbsResponseData` in the case of an OCSP response, and the
    /// data nested in the `digitally-signed` construct for TLS 1.2 signed
    /// data.
    data: untrusted::Input<'a>,

    /// The value of the `AlgorithmIdentifier`. This would be
    /// `signatureAlgorithm` in the case of an X.509 certificate or OCSP
    /// response. This would have to be synthesized in the case of TLS 1.2
    /// signed data, since TLS does not identify algorithms by ASN.1 OIDs.
    pub algorithm: untrusted::Input<'a>,

    /// The value of the signature. This would be `signature` in an X.509
    /// certificate or OCSP response. This would be the value of
    /// `DigitallySigned.signature` for TLS 1.2 signed data.
    signature: untrusted::Input<'a>,
}

/// Parses the concatenation of "tbs||signatureAlgorithm||signature" that
/// is common in the X.509 certificate and OCSP response syntaxes.
///
/// X.509 Certificates (RFC 5280) look like this:
///
/// ```ASN.1
/// Certificate (SEQUENCE) {
///     tbsCertificate TBSCertificate,
///     signatureAlgorithm AlgorithmIdentifier,
///     signatureValue BIT STRING
/// }
///
/// OCSP responses (RFC 6960) look like this:
///
/// ```ASN.1
/// BasicOCSPResponse {
///     tbsResponseData ResponseData,
///     signatureAlgorithm AlgorithmIdentifier,
///     signature BIT STRING,
///     certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
/// ```
///
/// Note that this function does NOT parse the outermost `SEQUENCE` or the
/// `certs` value.
///
/// The return value's first component is the contents of
/// `tbsCertificate`/`tbsResponseData`; the second component is a `SignedData`
/// structure that can be passed to `verify_signed_data`.
pub fn parse_signed_data<'a>(der: &mut untrusted::Reader<'a>)
                             -> Result<(untrusted::Input<'a>, SignedData<'a>),
                                       Error> {
    let mark1 = der.mark();
    let tbs = try!(der::expect_tag_and_get_value(der, der::Tag::Sequence));
    let mark2 = der.mark();
    let data = der.get_input_between_marks(mark1, mark2).unwrap();
    let algorithm = try!(der::expect_tag_and_get_value(der,
                                                       der::Tag::Sequence));
    let signature = try!(der::bit_string_with_no_unused_bits(der));

    Ok((tbs,
        SignedData {
            data: data,
            algorithm: algorithm,
            signature: signature
        }))
}

/// Verify `signed_data` using the public key in the DER-encoded
/// SubjectPublicKeyInfo `spki` using one of the algorithms in
/// `supported_algorithms`.
///
/// The algorithm is chosen based on the algorithm information encoded in the
/// algorithm identifiers in `public_key` and `signed_data.algorithm`. The
/// ordering of the algorithms in `supported_algorithms` does not really matter,
/// but generally more common algorithms should go first, as it is scanned
/// linearly for matches.
pub fn verify_signed_data(supported_algorithms: &[&SignatureAlgorithm],
                          spki_value: untrusted::Input,
                          signed_data: &SignedData) -> Result<(), Error> {
    // We need to verify the signature in `signed_data` using the public key
    // in `public_key`. In order to know which *ring* signature verification
    // algorithm to use, we need to know the public key algorithm (ECDSA,
    // RSA PKCS#1, etc.), the curve (if applicable), and the digest algorithm.
    // `signed_data` identifies only the public key algorithm and the digest
    // algorithm, and `public_key` identifies only the public key algorithm and
    // the curve (if any). Thus, we have to combine information from both
    // inputs to figure out which `ring::signature::VerificationAlgorithm` to
    // use to verify the signature.
    //
    // This is all further complicated by the fact that we don't have any
    // implicit knowledge about any algorithms or identifiers, since all of
    // that information is encoded in `supported_algorithms.` In particular, we
    // avoid hard-coding any of that information so that (link-time) dead code
    // elimination will work effectively in eliminating code for unused
    // algorithms.

    // Parse the signature.
    //
    let mut found_signature_alg_match = false;
    for supported_alg in supported_algorithms.iter()
            .filter(|alg| alg.signature_alg_id
                             .matches_algorithm_id_value(signed_data.algorithm)) {
        match verify_signature(supported_alg, spki_value, signed_data.data,
                               signed_data.signature) {
            Err(Error::UnsupportedSignatureAlgorithmForPublicKey) => {
                found_signature_alg_match = true;
                continue;
            },
            result => { return result; },
        }
    }

    if found_signature_alg_match {
        Err(Error::UnsupportedSignatureAlgorithmForPublicKey)
    } else {
        Err(Error::UnsupportedSignatureAlgorithm)
    }
}

pub fn verify_signature(signature_alg: &SignatureAlgorithm,
                        spki_value: untrusted::Input, msg: untrusted::Input,
                        signature: untrusted::Input) -> Result<(), Error> {
    let spki = try!(parse_spki_value(spki_value));
    if !signature_alg.public_key_alg_id
                     .matches_algorithm_id_value(spki.algorithm_id_value) {
        return Err(Error::UnsupportedSignatureAlgorithmForPublicKey);
    }
    signature::verify(signature_alg.verification_alg, spki.key_value, msg,
                      signature)
        .map_err(|_| Error::InvalidSignatureForPublicKey)
}


struct SubjectPublicKeyInfo<'a> {
    algorithm_id_value: untrusted::Input<'a>,
    key_value: untrusted::Input<'a>,
}

// Parse the public key into an algorithm OID, an optional curve OID, and the
// key value. The caller needs to check whether these match the
// `PublicKeyAlgorithm` for the `SignatureAlgorithm` that is matched when
// parsing the signature.
fn parse_spki_value(input: untrusted::Input)
                    -> Result<SubjectPublicKeyInfo, Error> {
    input.read_all(Error::BadDER, |input| {
        let algorithm_id_value =
                try!(der::expect_tag_and_get_value(input, der::Tag::Sequence));
        let key_value = try!(der::bit_string_with_no_unused_bits(input));
        Ok(SubjectPublicKeyInfo {
            algorithm_id_value: algorithm_id_value,
            key_value: key_value,
        })
    })
}


/// A signature algorithm.
pub struct SignatureAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    verification_alg: &'static signature::VerificationAlgorithm,
}

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P256,
    signature_alg_id: ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P256,
    signature_alg_id: ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P384,
    signature_alg_id: ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P384,
    signature_alg_id: ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

/// RSA PKCS#1 1.5 signatures using SHA-1 for keys of 2048-8192 bits.
/// Deprecated.
pub static RSA_PKCS1_2048_8192_SHA1: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA1,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA256,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA512,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: SignatureAlgorithm =
        SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA256,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
};

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: SignatureAlgorithm =
        SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA384,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
};

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: SignatureAlgorithm =
        SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA512,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
};

struct AlgorithmIdentifier {
    asn1_id_value: &'static [u8],
}

impl AlgorithmIdentifier {
    fn matches_algorithm_id_value(&self, encoded: untrusted::Input) -> bool {
        encoded == self.asn1_id_value
    }
}

// See src/data/README.md.

const ECDSA_P256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p256.der"),
};

const ECDSA_P384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p384.der"),
};

const ECDSA_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-sha256.der"),
};

const ECDSA_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-sha384.der"),
};

const RSA_ENCRYPTION: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-encryption.der"),
};

const RSA_PKCS1_SHA1: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha1.der"),
};

const RSA_PKCS1_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha256.der"),
};

const RSA_PKCS1_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha384.der"),
};

const RSA_PKCS1_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha512.der"),
};

const RSA_PSS_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha256.der"),
};

const RSA_PSS_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha384.der"),
};

const RSA_PSS_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha512.der"),
};
