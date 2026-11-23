use sha2::{Digest, Sha256};

mod entropy;
mod mnemonic;

use entropy::check_len;
pub use entropy::{EntropySource, OsEntropy, generate_entropy, generate_entropy_with};
pub use mnemonic::{
    entropy_to_mnemonic, generate_mnemonic, mnemonic_to_entropy, validate_mnemonic, wordlist,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidEntropyLength(usize),
    Rng,
    /// Число слов не из {12, 15, 18, 21, 24}.
    InvalidWordCount(usize),
    /// Слова нет в wordlist; позиция слова во фразе (с нуля).
    UnknownWord(usize),
    InvalidChecksum,
}

/// Шаг 2: checksum = первые ENT/32 бит SHA-256(entropy).
/// ENT/32 <= 8 для всех допустимых длин, поэтому хватает одного байта.
/// Возвращает (значение checksum, число бит).
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
