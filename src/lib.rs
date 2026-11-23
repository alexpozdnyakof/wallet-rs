//! A from-scratch implementation of [BIP-39] mnemonic codes, written for learning.
//!
//! **Not audited. Do not use it to protect real funds.**
//!
//! The pipeline is: entropy → checksum → 11-bit groups → words → seed.
//!
//! ```
//! use bip39::{entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed, validate_mnemonic};
//!
//! // 128 bits of entropy become 12 words (use `generate_mnemonic` for random ones).
//! let phrase = entropy_to_mnemonic(&[0x7f; 16]).unwrap().join(" ");
//! assert_eq!(
//!     phrase,
//!     "legal winner thank year wave sausage worth useful legal winner thank yellow"
//! );
//!
//! // The checksum catches typos and the words decode back to the entropy.
//! assert!(validate_mnemonic(&phrase).is_ok());
//! assert_eq!(&mnemonic_to_entropy(&phrase).unwrap()[..], &[0x7f; 16]);
//!
//! // The seed depends on the optional passphrase: a different one gives a different wallet.
//! let seed = mnemonic_to_seed(&phrase, "my passphrase");
//! assert_eq!(seed.len(), 64);
//! ```
//!
//! # Features
//!
//! - `wasm-js`: enables the browser/Node random source for `wasm32-unknown-unknown`.
//!
//! [BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use sha2::{Digest, Sha256};

mod entropy;
mod mnemonic;
mod seed;

use entropy::check_len;
pub use entropy::{EntropySource, OsEntropy, generate_entropy, generate_entropy_with};
pub use mnemonic::{
    entropy_to_mnemonic, generate_mnemonic, mnemonic_to_entropy, validate_mnemonic, wordlist,
};
pub use seed::{SEED_LEN, mnemonic_to_seed};

/// Errors returned by this crate.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Entropy length in bytes is not one of 16, 20, 24, 28, 32.
    InvalidEntropyLength(usize),
    /// The random source failed.
    Rng,
    /// The phrase does not have 12, 15, 18, 21 or 24 words.
    InvalidWordCount(usize),
    /// A word is not in the wordlist; holds its zero-based position in the phrase.
    UnknownWord(usize),
    /// The words are valid but the embedded checksum does not match.
    InvalidChecksum,
}

/// Computes the BIP-39 checksum: the first `ENT / 32` bits of `SHA-256(entropy)`.
///
/// Returns `(value, bit_count)`. The count is 4 for 128-bit entropy up to 8
/// for 256-bit entropy, so the value always fits in one byte.
///
/// ```
/// assert_eq!(bip39::checksum(&[0u8; 16]), Ok((0b0011, 4)));
/// ```
pub fn checksum(entropy: &[u8]) -> Result<(u8, usize), Error> {
    check_len(entropy.len())?;
    let cs_bits = entropy.len() * 8 / 32;
    let hash = Sha256::digest(entropy);
    // берём старшие cs_bits бит первого байта хеша
    Ok((hash[0] >> (8 - cs_bits), cs_bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Вектор из официального trezor/python-mnemonic:
    // entropy 00..00 (16 байт) -> "abandon ... about"
    // последнее слово "about" = индекс 3 = 0b0000_0000_011,
    // т.е. checksum (4 бита) = 0b0011 = 3.
    #[test]
    fn checksum_zero_entropy_128() {
        assert_eq!(checksum(&[0u8; 16]), Ok((0b0011, 4)));
    }

    // entropy 7f..7f -> "legal winner thank year wave sausage worth useful legal winner thank yellow"
    // последнее слово "yellow" = 2040 = 0b1111111_1000, checksum = 0b1000 = 8.
    #[test]
    fn checksum_7f_entropy_128() {
        assert_eq!(checksum(&[0x7f; 16]), Ok((0b1000, 4)));
    }
}
