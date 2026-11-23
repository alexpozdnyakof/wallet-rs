use std::sync::LazyLock;

use crate::{Error, checksum, generate_entropy};

const WORDLIST_RAW: &str = include_str!("wordlists/english.txt");

/// 2048 слов; индекс слова = 11-битное число.
static WORDLIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORDLIST_RAW.lines().collect());

pub fn wordlist() -> &'static [&'static str] {
    &WORDLIST
}

/// Шаг 3–4: entropy ‖ checksum, нарезка по 11 бит, индекс -> слово.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Vec<&'static str>, Error> {
    let (cs, cs_bits) = checksum(entropy)?;
    let words = wordlist();

    let mut out = Vec::with_capacity((entropy.len() * 8 + cs_bits) / 11);
    // Накопитель: в младших `nbits` битах лежат ещё не выданные биты.
    // После добавления байта nbits <= 10 + 8 = 18, в u32 помещается.
    let mut acc: u32 = 0;
    let mut nbits = 0;

    let mut push = |value: u8, bits: usize| {
        acc = (acc << bits) | value as u32;
        nbits += bits;
        while nbits >= 11 {
            let idx = (acc >> (nbits - 11)) & 0x7ff;
            out.push(words[idx as usize]);
            nbits -= 11;
        }
    };

    for &byte in entropy {
        push(byte, 8);
    }
    push(cs, cs_bits);

    debug_assert_eq!(nbits, 0);
    Ok(out)
}

/// Новая мнемоника из энтропии ОС.
pub fn generate_mnemonic(entropy_bytes: usize) -> Result<Vec<&'static str>, Error> {
    entropy_to_mnemonic(&generate_entropy(entropy_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase(entropy: &[u8]) -> String {
        entropy_to_mnemonic(entropy).unwrap().join(" ")
    }

    #[test]
    fn wordlist_is_2048_sorted_unique() {
        let w = wordlist();
        assert_eq!(w.len(), 2048);
        assert!(w.windows(2).all(|p| p[0] < p[1]));
    }

    // Официальные векторы trezor/python-mnemonic (vectors.json)
    #[test]
    fn vector_zeros_128() {
        assert_eq!(
            phrase(&[0x00; 16]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn vector_7f_128() {
        assert_eq!(
            phrase(&[0x7f; 16]),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
    }

    #[test]
    fn vector_80_128() {
        assert_eq!(
            phrase(&[0x80; 16]),
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        );
    }

    #[test]
    fn vector_ff_128() {
        assert_eq!(
            phrase(&[0xff; 16]),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }

    #[test]
    fn vector_zeros_192() {
        assert_eq!(
            phrase(&[0x00; 24]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
        );
    }

    #[test]
    fn vector_zeros_256() {
        assert_eq!(
            phrase(&[0x00; 32]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn word_counts() {
        for (bytes, words) in [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)] {
            assert_eq!(generate_mnemonic(bytes).unwrap().len(), words);
        }
    }

    #[test]
    fn rejects_bad_length() {
        assert_eq!(entropy_to_mnemonic(&[0; 15]), Err(Error::InvalidEntropyLength(15)));
    }
}
