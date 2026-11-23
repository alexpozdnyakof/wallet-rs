use std::sync::LazyLock;

use zeroize::Zeroizing;

use crate::{Error, checksum, generate_entropy};

const WORDLIST_RAW: &str = include_str!("wordlists/english.txt");

// 2048 words; a word's index is its 11-bit value.
static WORDLIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORDLIST_RAW.lines().collect());

/// The 2048-word English wordlist, sorted, so a word's index is its 11-bit value.
pub fn wordlist() -> &'static [&'static str] {
    &WORDLIST
}

/// Encodes entropy as mnemonic words.
///
/// Appends the checksum to the entropy, splits the bits into 11-bit groups
/// and maps each group to a word. 16, 20, 24, 28 or 32 bytes give 12, 15,
/// 18, 21 or 24 words.
///
/// ```
/// let words = bip39::entropy_to_mnemonic(&[0u8; 16]).unwrap();
/// assert_eq!(words.len(), 12);
/// assert_eq!(words[11], "about");
/// ```
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

/// Decodes a phrase back into entropy and verifies its checksum.
///
/// The inverse of [`entropy_to_mnemonic`]. Words may be separated by any
/// whitespace.
///
/// ```
/// use bip39::{Error, mnemonic_to_entropy};
///
/// let ok = "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// assert_eq!(&mnemonic_to_entropy(ok).unwrap()[..], &[0x7f; 16]);
///
/// let typo = "legal winner thank year wave sausage worth useful legal winner thank yelloww";
/// assert_eq!(mnemonic_to_entropy(typo), Err(Error::UnknownWord(11)));
/// ```
pub fn mnemonic_to_entropy(phrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(Error::InvalidWordCount(words.len()));
    }
    let total_bits = words.len() * 11;
    let cs_bits = total_bits / 33;

    let list = wordlist();
    let mut entropy = Zeroizing::new(Vec::with_capacity((total_bits - cs_bits) / 8));
    // Накопитель: после добавления слова nbits <= 7 + 11 = 18, влезает в u32.
    let mut acc: u32 = 0;
    let mut nbits = 0;

    for (pos, word) in words.iter().enumerate() {
        // wordlist отсортирован, значит работает бинарный поиск
        let idx = list.binary_search(word).map_err(|_| Error::UnknownWord(pos))?;
        acc = (acc << 11) | idx as u32;
        nbits += 11;
        while nbits >= 8 && entropy.len() < (total_bits - cs_bits) / 8 {
            entropy.push((acc >> (nbits - 8)) as u8);
            nbits -= 8;
        }
    }

    // После всей энтропии в накопителе остались ровно биты checksum.
    debug_assert_eq!(nbits, cs_bits);
    let given = (acc & ((1 << cs_bits) - 1)) as u8;
    let (expected, _) = checksum(&entropy)?;
    if given != expected {
        return Err(Error::InvalidChecksum);
    }
    Ok(entropy)
}

/// Checks the word count, the words and the checksum of a phrase.
pub fn validate_mnemonic(phrase: &str) -> Result<(), Error> {
    mnemonic_to_entropy(phrase).map(|_| ())
}

/// Generates a new random mnemonic from OS entropy.
///
/// `entropy_bytes` is one of 16, 20, 24, 28, 32.
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
    fn roundtrip_all_sizes() {
        for bytes in [16, 20, 24, 28, 32] {
            let entropy = generate_entropy(bytes).unwrap();
            let phrase = entropy_to_mnemonic(&entropy).unwrap().join(" ");
            assert_eq!(&mnemonic_to_entropy(&phrase).unwrap()[..], &entropy[..]);
        }
    }

    #[test]
    fn decode_known_vector() {
        let e = mnemonic_to_entropy(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        assert_eq!(&e[..], &[0x7f; 16]);
    }

    #[test]
    fn rejects_bad_checksum() {
        // последнее слово заменено: about -> abandon
        let p = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(validate_mnemonic(p), Err(Error::InvalidChecksum));
    }

    #[test]
    fn rejects_unknown_word_with_position() {
        let p = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert_eq!(validate_mnemonic(p), Err(Error::UnknownWord(11)));
    }

    #[test]
    fn rejects_bad_word_count() {
        assert_eq!(validate_mnemonic("abandon abandon"), Err(Error::InvalidWordCount(2)));
        assert_eq!(validate_mnemonic(""), Err(Error::InvalidWordCount(0)));
    }

    #[test]
    fn tolerates_extra_whitespace() {
        assert!(validate_mnemonic(
            "  legal winner  thank year wave sausage worth useful legal winner thank\tyellow\n"
        )
        .is_ok());
    }

    #[test]
    fn rejects_bad_length() {
        assert_eq!(entropy_to_mnemonic(&[0; 15]), Err(Error::InvalidEntropyLength(15)));
    }
}
